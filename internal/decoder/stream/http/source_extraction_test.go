package http

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/andybalholm/brotli"
	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/file"
	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
)

type sourceFileWriter struct {
	netio.AuditRecordWriter
	records []*types.File
}

func (w *sourceFileWriter) Write(m proto.Message) error {
	w.records = append(w.records, proto.Clone(m).(*types.File))
	return nil
}

func captureExtractedHTTP(t *testing.T, data core.DataFragments, source bool) ([]*types.HTTP, []*types.File) {
	t.Helper()
	return captureHTTPWithPayloadOption(t, data, source, false)
}

func captureHTTPWithPayloadOption(t *testing.T, data core.DataFragments, source, includePayloads bool) ([]*types.HTTP, []*types.File) {
	t.Helper()
	return captureHTTPWithBodyLimit(t, data, source, includePayloads, 0)
}

func captureHTTPWithBodyLimit(t *testing.T, data core.DataFragments, source, includePayloads bool, limit int64) ([]*types.HTTP, []*types.File) {
	t.Helper()
	previous, oldConfig := decoderconfig.Instance, file.GetGlobalConfig()
	writer, count, fileWriter, fileCount := Decoder.Writer, Decoder.NumRecordsWritten, file.Decoder.Writer, file.Decoder.NumRecordsWritten
	t.Cleanup(func() {
		decoderconfig.Instance = previous
		file.SetGlobalConfig(oldConfig)
		Decoder.Writer, Decoder.NumRecordsWritten = writer, count
		file.Decoder.Writer, file.Decoder.NumRecordsWritten = fileWriter, fileCount
		file.ResetDedupCache()
	})
	decoderconfig.Instance = decoderconfig.DefaultConfig.Clone()
	decoderconfig.Instance.Out = t.TempDir()
	decoderconfig.Instance.FileStorage = "files"
	decoderconfig.Instance.IncludePayloads = includePayloads
	decoderconfig.Instance.WriteIncomplete = true
	cfg := file.GetDefaultConfig()
	cfg.FileExtraction.Advanced.UseMagicDetection = false
	if limit > 0 {
		cfg.FileExtraction.SizeLimits.MaxFileSize = limit
	}
	file.SetGlobalConfig(cfg)
	w, fw := &httpEvidenceWriter{}, &sourceFileWriter{}
	Decoder.Writer = w
	file.Decoder.Writer = fw
	c := &core.ConversationInfo{Ident: "fixture", CommunityID: "1:fixture", ClientIP: "192.0.2.1", ServerIP: "192.0.2.2", ClientPort: 40000, ServerPort: 80, Data: data}
	if source {
		var client, server core.SliceSource
		for _, fragment := range data {
			if core.FromServer(fragment) {
				server = append(server, fragment)
			} else {
				client = append(client, fragment)
			}
		}
		c.Data = nil
		c.ClientSource, c.ServerSource = client, server
		c.Source = core.MergedSource{Client: client, Server: server}
		c.StateBudget, _ = core.NewStateBudget(262144, nil)
		c.LoadData = func() error { t.Fatal("extraction unexpectedly materialized the conversation"); return nil }
	}
	(&httpReader{conversation: c}).Decode()
	if c.FragmentError != nil {
		t.Fatal(c.FragmentError)
	}
	if source && c.StateBudget.Health().RetainedBytes != 0 {
		t.Fatal("source budget leaked", c.StateBudget.Health())
	}
	for _, record := range fw.records {
		got, err := os.ReadFile(record.Location)
		if err != nil {
			t.Fatal(err)
		}
		if file.ComputeHashes(got).SHA256 != record.Hashes.SHA256 {
			t.Fatal("file evidence hash mismatch")
		}
		record.Location = ""
	}
	entries, err := os.ReadDir(filepath.Join(decoderconfig.Instance.Out, ".artifact-scratch"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatal("scratch files survived extraction", entries)
	}
	return w.records, fw.records
}

func TestHTTPSourceOrientationUnderOneDirectionBudget(t *testing.T) {
	budget, err := core.NewStateBudget(16<<10, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := &core.ConversationInfo{
		ClientIP: "192.0.2.2", ServerIP: "192.0.2.1", StateBudget: budget,
		ClientSource: core.SliceSource{wireFragment(0, []byte("HTTP/1.1 204 No Content\r\n\r\n"), 1)},
		ServerSource: core.SliceSource(nil),
	}
	oriented, err := sourceHTTPOrientation(c)
	if err != nil {
		t.Fatal(err)
	}
	if oriented.ServerIP != c.ClientIP || oriented.ClientSource.Count() != 0 || oriented.ServerSource.Count() != 1 {
		t.Fatal("response-only conversation was not oriented correctly")
	}
	if health := budget.Health(); health.RetainedBytes != 0 || health.PeakBytes != 16<<10 || health.Exceeded {
		t.Fatalf("unexpected prefix accounting: %+v", health)
	}
}

func TestHTTPSourcePreflightScansBodiesUnderFiniteBudget(t *testing.T) {
	body := strings.Repeat("fixture data\n", 20000)
	request := fmt.Sprintf("POST /upload HTTP/1.1\r\nHost: fixture.test\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	var source core.SliceSource
	for part := range slices.Chunk([]byte(request+request), 1024) {
		source = append(source, wireFragment(0, part, 1))
	}
	budget, err := core.NewStateBudget(24<<10, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := &core.ConversationInfo{ClientSource: source, StateBudget: budget}
	if err := preflightSourceHTTP(c); err != nil {
		t.Fatal(err)
	}
	c.ClientSource = append(source, wireFragment(0, []byte("POST /encoded HTTP/1.1\r\nHost: fixture.test\r\nContent-Encoding: br\r\nContent-Length: 4\r\n\r\ndata"), 1))
	if err := preflightSourceHTTP(c); err != errHTTPSourceCompatibility {
		t.Fatalf("preflight missed trailing request requiring compatibility: %v", err)
	}
	health := budget.Health()
	if health.RetainedBytes != 0 || health.Exceeded {
		t.Fatalf("preflight leaked or exceeded state: %+v", health)
	}
	t.Logf("scanned %d body bytes across two requests; peak TCP state %d bytes", 2*len(body), health.PeakBytes)
}

func TestHTTPSourcePreflightStopsAtOpaqueBodyLimit(t *testing.T) {
	oldDecoder, oldFile := decoderconfig.Instance, file.GetGlobalConfig()
	t.Cleanup(func() {
		decoderconfig.Instance = oldDecoder
		file.SetGlobalConfig(oldFile)
	})
	decoderconfig.Instance = &decoderconfig.Config{FileStorage: "files"}
	cfg := file.GetDefaultConfig()
	cfg.FileExtraction.SizeLimits.MaxFileSize = 128
	file.SetGlobalConfig(cfg)
	for _, method := range []string{"PUT", "POST"} {
		for _, size := range []int{128, 129} {
			wire := fmt.Sprintf("%s /fixture HTTP/1.1\r\nHost: fixture.test\r\nContent-Length: %d\r\n\r\n%sPOST /encoded HTTP/1.1\r\nHost: fixture.test\r\nContent-Encoding: br\r\nContent-Length: 4\r\n\r\ndata", method, size, strings.Repeat("x", size))
			c := &core.ConversationInfo{ClientSource: core.SliceSource{wireFragment(0, []byte(wire), 1)}}
			var want error
			if size == 128 {
				want = errHTTPSourceCompatibility
			}
			if err := preflightSourceHTTP(c); err != want {
				t.Fatalf("%s body size %d: preflight returned %v, want %v", method, size, err, want)
			}
		}
	}
}

func TestHTTPSourceOversizedPostPreservesOnlyAllowedPrefix(t *testing.T) {
	body := strings.Repeat("x", 128) + "y"
	wire := fmt.Sprintf("POST /fixture.bin HTTP/1.1\r\nHost: fixture.test\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\n\r\n%sPOST /encoded HTTP/1.1\r\nHost: fixture.test\r\nContent-Encoding: br\r\nContent-Length: 4\r\n\r\ndata", len(body), body)
	data := core.DataFragments{wireFragment(0, []byte(wire), 1)}
	rows, artifacts := captureHTTPWithBodyLimit(t, data, true, false, 128)
	if len(rows) != 1 || rows[0].URL != "/fixture.bin" {
		t.Fatalf("oversized request emitted unexpected observations: %v", rows)
	}
	want := file.ComputeHashes([]byte(body[:128])).SHA256
	if len(artifacts) != 1 || artifacts[0].IsComplete || artifacts[0].Length != 128 || artifacts[0].GetHashes().GetSHA256() != want {
		t.Fatalf("unexpected incomplete artifact: %v", artifacts)
	}
}

func TestHTTPSourceBodylessExchangeSkipsScratch(t *testing.T) {
	data := core.DataFragments{
		wireFragment(0, []byte("GET /empty?label=fixture HTTP/1.1\r\nHost: fixture.test\r\n\r\n"), 1),
		wireFragment(1, []byte("HTTP/1.1 204 No Content\r\n\r\n"), 2),
	}
	want, wantFiles := captureExtractedHTTP(t, data, false)
	got, gotFiles := captureExtractedHTTP(t, data, true)
	if len(got) != 1 || len(gotFiles) != 0 || !reflect.DeepEqual(want, got) || !reflect.DeepEqual(wantFiles, gotFiles) {
		t.Fatalf("bodyless source changed audit evidence: want %v, got %v, files %v", want, got, gotFiles)
	}
	if _, err := os.Stat(filepath.Join(decoderconfig.Instance.Out, ".artifact-scratch")); !os.IsNotExist(err) {
		t.Fatalf("bodyless exchange touched artifact scratch: %v", err)
	}
}

func TestHTTPSourceOpaquePutSkipsScratch(t *testing.T) {
	for _, chunked := range []bool{false, true} {
		t.Run(fmt.Sprintf("chunked=%t", chunked), func(t *testing.T) {
			testHTTPSourceOpaquePutSkipsScratch(t, chunked)
		})
	}
}

func testHTTPSourceOpaquePutSkipsScratch(t *testing.T, chunked bool) {
	t.Helper()
	body := strings.Repeat("fixture payload\n", 8192)
	framed := fmt.Sprintf("Content-Length: %d\r\n\r\n%s", len(body), body)
	if chunked {
		framed = fmt.Sprintf("Transfer-Encoding: chunked\r\n\r\n%x\r\n%s\r\n0\r\n\r\n", len(body), body)
	}
	request := "PUT /fixture HTTP/1.1\r\nHost: fixture.test\r\n" + framed + "GET /next HTTP/1.1\r\nHost: fixture.test\r\n\r\n"
	var data core.DataFragments
	for fragment := range slices.Chunk([]byte(request), 8192) {
		data = append(data, wireFragment(0, fragment, 1))
	}
	data = append(data, wireFragment(1, []byte(strings.Repeat("HTTP/1.1 204 No Content\r\n\r\n", 2)), 2))
	want, wantFiles := captureExtractedHTTP(t, data, false)
	got, gotFiles := captureExtractedHTTP(t, data, true)
	if len(got) != 2 || got[1].URL != "/next" || len(gotFiles) != 0 || !reflect.DeepEqual(want, got) || !reflect.DeepEqual(wantFiles, gotFiles) {
		t.Fatalf("PUT changed audit evidence or pairing: want %v, got %v, files %v", want, got, gotFiles)
	}
	if _, err := os.Stat(filepath.Join(decoderconfig.Instance.Out, ".artifact-scratch")); !os.IsNotExist(err) {
		t.Fatalf("opaque PUT touched artifact scratch: %v", err)
	}
}

func TestCappedSourceRequestBodyStopsAtLimit(t *testing.T) {
	previous := file.GetGlobalConfig()
	t.Cleanup(func() { file.SetGlobalConfig(previous) })
	cfg := file.GetDefaultConfig()
	cfg.FileExtraction.SizeLimits.MaxFileSize = 128
	file.SetGlobalConfig(cfg)
	for _, size := range []int{128, 1024} {
		body := strings.NewReader(strings.Repeat("x", size))
		sample, release, err := readCappedSourceRequestBody(&core.ConversationInfo{}, body)
		release()
		if len(sample) != 128 || size-body.Len() != min(size, 129) || (size == 128 && err != nil) || (size > 128 && !errors.Is(err, file.ErrArtifactLimit)) {
			t.Fatalf("size %d: sampled %d, read %d, err %v", size, len(sample), size-body.Len(), err)
		}
	}
}

func TestHTTPSourceIncludesPairedPayloads(t *testing.T) {
	body := strings.Repeat("binary fixture\x00", 10000)
	request := fmt.Sprintf("POST /upload HTTP/1.1\r\nHost: fixture.test\r\nContent-Length: %d\r\n\r\n%sGET /next HTTP/1.1\r\nHost: fixture.test\r\n\r\n", len(body), body)
	response := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%sHTTP/1.1 204 No Content\r\n\r\n", len(body), body)
	var data core.DataFragments
	for side, wire := range []string{request, response} {
		for fragment := range slices.Chunk([]byte(wire), 8192) {
			data = append(data, wireFragment(side, fragment, int64(side+1)))
		}
	}
	want, wantFiles := captureHTTPWithPayloadOption(t, data, false, true)
	got, files := captureHTTPWithPayloadOption(t, data, true, true)
	if !reflect.DeepEqual(got, want) || !reflect.DeepEqual(files, wantFiles) {
		t.Fatal("payload source changed HTTP or file evidence")
	}
	if len(got) != 2 || string(got[0].RequestBody) != body || string(got[0].ResponseBody) != body || got[1].URL != "/next" {
		t.Fatal("incomplete payloads or transaction pairing")
	}
}

func TestHTTPRecordBorrowsRetainedResponsePayload(t *testing.T) {
	previous := decoderconfig.Instance
	t.Cleanup(func() { decoderconfig.Instance = previous })
	decoderconfig.Instance = decoderconfig.DefaultConfig.Clone()
	decoderconfig.Instance.IncludePayloads = true
	body := bytes.Repeat([]byte("response"), 1<<16)
	record := httpFromResponseBody(&http.Response{ContentLength: -1}, body, nil)
	if record.ResContentLength != int32(len(body)) || len(record.ResponseBody) != len(body) || &record.ResponseBody[0] != &body[0] {
		t.Fatal("plain response body was copied or truncated during record construction")
	}
}

func TestBackedGzipResponseClassificationExpansionLimit(t *testing.T) {
	oldDecoder, oldFile := decoderconfig.Instance, file.GetGlobalConfig()
	t.Cleanup(func() { decoderconfig.Instance = oldDecoder; file.SetGlobalConfig(oldFile) })
	decoderconfig.Instance = decoderconfig.DefaultConfig.Clone()
	decoderconfig.Instance.Out = t.TempDir()
	cfg := file.GetDefaultConfig()
	const limit = 4096
	cfg.FileExtraction.SizeLimits.MaxFileSize = limit
	file.SetGlobalConfig(cfg)
	for _, size := range []int{limit, limit + 1} {
		var wire bytes.Buffer
		w := gzip.NewWriter(&wire)
		if _, err := w.Write(bytes.Repeat([]byte("x"), size)); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		spool, err := file.SpoolBody(&wire)
		if err != nil {
			t.Fatal(err)
		}
		budget, _ := core.NewStateBudget(128<<10, nil)
		c := &core.ConversationInfo{StateBudget: budget}
		detected := sourceResponseContentType(c, spool, "gzip")
		if err := spool.Close(); err != nil {
			t.Fatal(err)
		}
		want := "text/plain; charset=utf-8"
		if size > limit {
			want = ""
		}
		if detected != want || c.FragmentError != nil || budget.Health().RetainedBytes != 0 {
			t.Fatalf("expanded size %d: detected=%q error=%v credits=%+v", size, detected, c.FragmentError, budget.Health())
		}
	}
}

func TestHTTPSourceExtractionPreservesRecordsAndBodies(t *testing.T) {
	for _, kind := range []string{"identity", "gzip", "gzip-truncated", "deflate", "raw-deflate", "br", "truncated", "chunked-upload", "multipart-upload", "json-upload", "urlencoded-upload"} {
		t.Run(kind, func(t *testing.T) {
			body := []byte(strings.Repeat("artifact fixture\n", 5000))
			wire := body
			encoding := ""
			if kind == "gzip" || kind == "gzip-truncated" {
				var output bytes.Buffer
				writer := gzip.NewWriter(&output)
				_, _ = writer.Write(body)
				if err := writer.Close(); err != nil {
					t.Fatal(err)
				}
				wire = output.Bytes()
				if kind == "gzip-truncated" {
					wire = wire[:len(wire)-1]
				}
				encoding = "Content-Encoding: gzip\r\n"
			}
			if kind == "deflate" || kind == "raw-deflate" || kind == "br" {
				var output bytes.Buffer
				var writer io.WriteCloser
				coding := "deflate"
				switch kind {
				case "raw-deflate":
					var err error
					writer, err = flate.NewWriter(&output, flate.DefaultCompression)
					if err != nil {
						t.Fatal(err)
					}
				case "br":
					writer, coding = brotli.NewWriter(&output), "br"
				default:
					writer = zlib.NewWriter(&output)
				}
				if _, err := writer.Write(body); err != nil {
					t.Fatal(err)
				}
				if err := writer.Close(); err != nil {
					t.Fatal(err)
				}
				wire, encoding = output.Bytes(), "Content-Encoding: "+coding+"\r\n"
			}
			length := len(wire)
			if kind == "truncated" {
				length += 100
			}
			request := "GET /file.txt HTTP/1.1\r\nHost: fixture.test\r\n\r\n"
			if kind == "chunked-upload" {
				request = "POST /upload.bin HTTP/1.1\r\nHost: fixture.test\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\n\r\n3\r\none\r\n0\r\n\r\nGET /file.txt HTTP/1.1\r\nHost: fixture.test\r\n\r\n"
			}
			if kind == "multipart-upload" {
				multipart := "--fixture\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"fixture.bin\"\r\n\r\n" + strings.Repeat("fixture bytes\n", 240000) + "\r\n--fixture\r\nContent-Disposition: form-data; name=\"label\"\r\n\r\nafter-file\r\n--fixture--\r\n"
				request = fmt.Sprintf("POST /upload?label=query HTTP/1.1\r\nHost: fixture.test\r\nContent-Type: multipart/form-data; boundary=fixture\r\nContent-Length: %d\r\n\r\n%sGET /next HTTP/1.1\r\nHost: fixture.test\r\n\r\n", len(multipart), multipart)
			}
			if kind == "json-upload" {
				const payload = `{"label":"from-body","count":1,"nested":{"label":"ignored"}}`
				request = fmt.Sprintf("POST /upload?label=query HTTP/1.1\r\nHost: fixture.test\r\nContent-Type: application/vnd.fixture+json\r\nContent-Length: %d\r\n\r\n%s", len(payload), payload)
			}
			if kind == "urlencoded-upload" {
				const payload = "label=from-body&label=second%2Bvalue&escaped=hello+there&bad=%XX"
				request = fmt.Sprintf("POST /upload?label=query HTTP/1.1\r\nHost: fixture.test\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\n\r\n%s", len(payload), payload)
			}
			response := []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n%sContent-Length: %d\r\n\r\n", encoding, length))
			response = append(response, wire...)
			data := core.DataFragments{}
			if kind == "multipart-upload" {
				response = append([]byte("HTTP/1.1 204 No Content\r\n\r\n"), response...)
			}
			for fragment := range slices.Chunk([]byte(request), 16<<10) {
				data = append(data, wireFragment(0, fragment, 1))
			}
			data = append(data, wireFragment(1, response, 2))
			wantHTTP, wantFiles := captureExtractedHTTP(t, data, false)
			gotHTTP, gotFiles := captureExtractedHTTP(t, data, true)
			if !reflect.DeepEqual(gotHTTP, wantHTTP) {
				t.Fatalf("HTTP observations changed:\ngot %v\nwant %v", gotHTTP, wantHTTP)
			}
			if !reflect.DeepEqual(gotFiles, wantFiles) {
				t.Fatalf("file observations changed:\ngot %v\nwant %v", gotFiles, wantFiles)
			}
			if (kind == "deflate" || kind == "raw-deflate" || kind == "br") && (len(gotFiles) != 1 || gotFiles[0].Hashes.SHA256 != file.ComputeHashes(body).SHA256) {
				t.Fatalf("artifact did not match decoded body: %v", gotFiles)
			}
			if kind == "multipart-upload" && (len(gotHTTP) != 2 || len(gotFiles) != 2 || !strings.Contains(fmt.Sprint(gotHTTP[0].Parameters), "after-file")) {
				t.Fatalf("multipart fields, file, or next message lost: %v / %d", gotHTTP, len(gotFiles))
			}
			if (kind == "json-upload" || kind == "urlencoded-upload") && (len(gotHTTP) != 1 || len(gotFiles) != 2 || !strings.Contains(fmt.Sprint(gotHTTP[0].Parameters), "from-body")) {
				t.Fatalf("form fields or files lost: %v / %d", gotHTTP, len(gotFiles))
			}
		})
	}
}
