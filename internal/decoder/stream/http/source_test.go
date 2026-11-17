package http

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"

	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/types"
)

func capturePassiveHTTP(t *testing.T, data core.DataFragments, source bool) ([]*types.HTTP, *core.ConversationInfo) {
	t.Helper()
	previous, writer, count := decoderconfig.Instance, Decoder.Writer, Decoder.NumRecordsWritten
	defer func() { decoderconfig.Instance, Decoder.Writer, Decoder.NumRecordsWritten = previous, writer, count }()
	decoderconfig.Instance = decoderconfig.DefaultConfig.Clone()
	decoderconfig.Instance.FileStorage = ""
	decoderconfig.Instance.Out = t.TempDir()
	decoderconfig.Instance.IncludePayloads = false
	w := &httpEvidenceWriter{}
	Decoder.Writer = w
	c := &core.ConversationInfo{Ident: "fixture", CommunityID: "1:fixture", ClientIP: "192.0.2.1", ServerIP: "192.0.2.2", ClientPort: 40000, ServerPort: 80, Data: data}
	if source {
		var client, server core.DataFragments
		for _, fragment := range data {
			if core.FromServer(fragment) {
				server = append(server, fragment)
			} else {
				client = append(client, fragment)
			}
		}
		c.Data = nil
		c.ClientSource, c.ServerSource = core.SliceSource(client), core.SliceSource(server)
		c.Source = core.MergedSource{Client: c.ClientSource, Server: c.ServerSource}
		c.StateBudget, _ = core.NewStateBudget(1<<20, nil)
		c.LoadData = func() error {
			if len(w.records) != 0 {
				t.Fatal("compatibility fallback followed emitted records")
			}
			c.Source = nil
			c.ClientSource, c.ServerSource = nil, nil
			c.Data = data
			return nil
		}
	}
	(&httpReader{conversation: c}).Decode()
	entries, err := os.ReadDir(filepath.Join(decoderconfig.Instance.Out, ".artifact-scratch"))
	if len(entries) != 0 || err != nil && !os.IsNotExist(err) {
		t.Fatalf("scratch cleanup: %v %v", entries, err)
	}
	return w.records, c
}

func TestHTTPSourceParsesPassiveForms(t *testing.T) {
	multipart := "--fixture\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"fixture.bin\"\r\n\r\n" + strings.Repeat("fixture bytes\n", 240000) + "\r\n--fixture\r\nContent-Disposition: form-data; name=\"label\"\r\n\r\nafter-file\r\n--fixture--\r\n"
	for _, request := range []string{
		"POST /login HTTP/1.1\r\nHost: fixture.test\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 8\r\n\r\nuser=one",
		"POST /api HTTP/1.1\r\nHost: fixture.test\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
		fmt.Sprintf("POST /upload HTTP/1.1\r\nHost: fixture.test\r\nContent-Type: multipart/form-data; boundary=fixture\r\nContent-Length: %d\r\n\r\n%s", len(multipart), multipart),
	} {
		var data core.DataFragments
		for fragment := range slices.Chunk([]byte(request+"GET /next HTTP/1.1\r\nHost: fixture.test\r\n\r\n"), 16<<10) {
			data = append(data, wireFragment(0, fragment, 1))
		}
		data = append(data, wireFragment(1, []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n"), 2))
		want, _ := capturePassiveHTTP(t, data, false)
		got, c := capturePassiveHTTP(t, data, true)
		if c.FragmentError != nil || c.Source == nil || !reflect.DeepEqual(want, got) || len(got) != 2 || got[1].URL != "/next" {
			t.Fatal("passive form changed results or entered compatibility", c.FragmentError, want, got)
		}
	}
}

func TestHTTPSourceSniffsBackedGzipUpload(t *testing.T) {
	var encoded bytes.Buffer
	writer, err := gzip.NewWriterLevel(&encoded, gzip.NoCompression)
	if err != nil {
		t.Fatal(err)
	}
	payload := "<html>" + strings.Repeat("fixture upload\n", 180000)
	if _, err := writer.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	wire := encoded.String()
	corrupt := []byte(wire)
	corrupt[len(corrupt)-8] ^= 1
	for _, tc := range []struct{ name, body, detected string }{
		{"valid", wire, "text/html; charset=utf-8"},
		{"truncated-footer", wire[:len(wire)-1], "application/x-gzip"},
		{"bad-checksum", string(corrupt), "application/x-gzip"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := fmt.Sprintf("POST /upload HTTP/1.1\r\nHost: fixture.test\r\nContent-Type: application/octet-stream\r\nContent-Encoding: gzip\r\nContent-Length: %d\r\n\r\n%sGET /next HTTP/1.1\r\nHost: fixture.test\r\n\r\n", len(tc.body), tc.body)
			var data core.DataFragments
			for fragment := range slices.Chunk([]byte(request), 16<<10) {
				data = append(data, wireFragment(0, fragment, 1))
			}
			data = append(data, wireFragment(1, []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n"), 2))
			want, _ := capturePassiveHTTP(t, data, false)
			got, c := capturePassiveHTTP(t, data, true)
			if c.FragmentError != nil || c.Source == nil || len(got) != 2 || got[0].ContentTypeDetected != tc.detected || !reflect.DeepEqual(want, got) {
				t.Fatalf("gzip result changed or materialized: %v, want %v, error %v", got, want, c.FragmentError)
			}
		})
	}
}

type generatedHTTPResponse struct {
	size, chunk int
	sample      func()
}

func TestHTTPSourceDrainsOpaqueRequestBodiesWithoutChangingMetadata(t *testing.T) {
	for _, body := range []string{"small", strings.Repeat("x", 8192)} {
		request := fmt.Sprintf("POST /upload HTTP/1.1\r\nHost: fixture.test\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
		data := core.DataFragments{wireFragment(0, []byte(request), 1), wireFragment(1, []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"), 2)}
		want, _ := capturePassiveHTTP(t, data, false)
		got, c := capturePassiveHTTP(t, data, true)
		if c.FragmentError != nil || c.Source == nil || !reflect.DeepEqual(want, got) || c.StateBudget.Health().RetainedBytes != 0 {
			t.Fatal("opaque body source changed metadata", c.FragmentError, want, got, c.StateBudget.Health())
		}
	}
	data := core.DataFragments{wireFragment(0, []byte("POST /upload HTTP/1.1\r\nHost: fixture.test\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\n\r\n3\r\none\r\n0\r\n\r\nGET /next HTTP/1.1\r\nHost: fixture.test\r\n\r\n"), 1), wireFragment(1, []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n"), 2)}
	want, _ := capturePassiveHTTP(t, data, false)
	got, c := capturePassiveHTTP(t, data, true)
	if c.FragmentError != nil || c.Source == nil || !reflect.DeepEqual(want, got) {
		t.Fatal("chunked opaque request crossed the next message", c.FragmentError, want, got)
	}
}

type panickingRequestBody struct{}

func (panickingRequestBody) Read([]byte) (int, error) { panic("control") }

func TestSourceRequestBodyCreditsReleaseOnPanic(t *testing.T) {
	budget, _ := core.NewStateBudget(65536, nil)
	c := &core.ConversationInfo{StateBudget: budget}
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("request body panic was suppressed")
			}
		}()
		_, _, _ = readSourceRequestBody(c, panickingRequestBody{})
	}()
	if budget.Health().RetainedBytes != 0 {
		t.Fatal("request body panic retained scratch/sample credits", budget.Health())
	}
}

func (s generatedHTTPResponse) Count() int64 { return 1 + int64((s.size+s.chunk-1)/s.chunk) }
func (s generatedHTTPResponse) Walk(yield func(core.DataFragment) bool) error {
	return s.WalkRange(0, s.Count(), yield)
}
func (s generatedHTTPResponse) WalkRange(start, count int64, yield func(core.DataFragment) bool) error {
	if err := core.CheckFragmentRange(s.Count(), start, count); err != nil {
		return err
	}
	data := bytes.Repeat([]byte("x"), s.chunk)
	for index := start; index < start+count; index++ {
		if index == s.Count()/2 && s.sample != nil {
			s.sample()
		}
		var payload []byte
		if index == 0 {
			payload = []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\nContent-Type: application/octet-stream\r\n\r\n", s.size))
		} else {
			payload = data[:min(s.chunk, s.size-int(index-1)*s.chunk)]
		}
		if !yield(wireFragment(1, payload, index+2)) {
			break
		}
	}
	return nil
}

func TestHTTPSourceDoesNotRetainLargeResponseBody(t *testing.T) {
	previous, writer, count := decoderconfig.Instance, Decoder.Writer, Decoder.NumRecordsWritten
	defer func() { decoderconfig.Instance, Decoder.Writer, Decoder.NumRecordsWritten = previous, writer, count }()
	decoderconfig.Instance = decoderconfig.DefaultConfig.Clone()
	decoderconfig.Instance.FileStorage = ""
	decoderconfig.Instance.IncludePayloads = false
	w := &httpEvidenceWriter{}
	Decoder.Writer = w
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	var retained int64
	body := generatedHTTPResponse{size: 90 << 20, chunk: 32768, sample: func() {
		runtime.GC()
		var now runtime.MemStats
		runtime.ReadMemStats(&now)
		retained = max(retained, int64(now.HeapAlloc)-int64(before.HeapAlloc))
	}}
	client := core.SliceSource{wireFragment(0, []byte("GET / HTTP/1.1\r\nHost: fixture.test\r\n\r\n"), 1)}
	c := &core.ConversationInfo{Ident: "fixture", ClientIP: "192.0.2.1", ServerIP: "192.0.2.2", ClientPort: 40000, ServerPort: 80, ClientSource: client, ServerSource: body}
	c.Source = core.MergedSource{Client: client, Server: body}
	c.StateBudget, _ = core.NewStateBudget(262144, nil)
	(&httpReader{conversation: c}).Decode()
	if c.FragmentError != nil || len(w.records) != 1 || w.records[0].ResContentLength != 90<<20 || c.StateBudget.Health().RetainedBytes != 0 {
		t.Fatal("large source response was not decoded", c.FragmentError, w.records, c.StateBudget.Health())
	}
	if retained > 4<<20 {
		t.Fatal("HTTP source retained body-sized input", retained)
	}
	t.Logf("body bytes=%d sampled retained heap delta=%d", body.size, retained)
}

func TestHTTPSourcePreservesPipeliningSplitsLossAndRoles(t *testing.T) {
	request := []byte("GET /a HTTP/1.1\r\nHost: fixture.test\r\n\r\nHEAD /b HTTP/1.1\r\nHost: fixture.test\r\n\r\n")
	response := []byte("HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\naHTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n")
	for _, reverse := range []bool{false, true} {
		for _, loss := range []int{0, -1, 3} {
			for split := 1; split < len(request); split++ {
				a, b := 0, 1
				if reverse {
					a, b = 1, 0
				}
				data := core.DataFragments{wireFragment(a, request[:split], 10), wireFragment(a, request[split:], 11), wireFragment(b, response, 12)}
				data[0].(*core.StreamData).SkippedBytes = loss
				want, _ := capturePassiveHTTP(t, data, false)
				got, c := capturePassiveHTTP(t, data, true)
				if c.FragmentError != nil || !reflect.DeepEqual(want, got) || c.StateBudget.Health().RetainedBytes != 0 {
					t.Fatalf("reverse=%v loss=%d split=%d: %v / %v error=%v budget=%+v", reverse, loss, split, want, got, c.FragmentError, c.StateBudget.Health())
				}
			}
		}
	}
}

func TestHTTPSourceQualifiesTruncatedPassiveResponse(t *testing.T) {
	data := core.DataFragments{wireFragment(0, []byte("GET / HTTP/1.1\r\nHost: fixture.test\r\n\r\n"), 1), wireFragment(1, []byte("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 100\r\n\r\nshort"), 2)}
	got, c := capturePassiveHTTP(t, data, true)
	if c.FragmentError != nil || len(got) != 1 || got[0].ReassemblyStatus != "incomplete_response_body" {
		t.Fatal("passive body failure disappeared", got, c.FragmentError)
	}
}

func TestHTTPSourceRecoversAfterInternalGapWithQualifiedPairing(t *testing.T) {
	data := core.DataFragments{
		wireFragment(0, []byte("GET /one HTTP/1.1\r\nHost: fixture.test\r\n\r\nGET /two HTTP/1.1\r\nHost: fixture.test\r\n\r\n"), 1),
		wireFragment(1, []byte("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort"), 2),
		&core.StreamData{Dir: wireFragment(1, nil, 3).Dir, SkippedBytes: 3},
		wireFragment(1, []byte("HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n"), 4),
	}
	want, _ := capturePassiveHTTP(t, data, false)
	got, c := capturePassiveHTTP(t, data, true)
	if c.FragmentError != nil || len(got) != 3 || !reflect.DeepEqual(want, got) {
		t.Fatal("source gap changed transaction recovery", c.FragmentError, want, got)
	}
}
