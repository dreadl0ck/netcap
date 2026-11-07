package http

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gopacket/gopacket"
)

func captureHTTP(t testing.TB, data core.DataFragments) []*types.HTTP {
	t.Helper()
	old, cfg, count := Decoder.Writer, config.Instance, Decoder.NumRecordsWritten
	defer func() { Decoder.Writer, config.Instance, Decoder.NumRecordsWritten = old, cfg, count }()
	w := &httpEvidenceWriter{}
	Decoder.Writer, config.Instance = w, &config.Config{IncludePayloads: true}
	c := &core.ConversationInfo{Ident: "192.0.2.1:50000->192.0.2.2:80", CommunityID: "1:fixture", ClientIP: "192.0.2.1", ServerIP: "192.0.2.2", ClientPort: 50000, ServerPort: 80, Data: data}
	(&httpReader{conversation: c}).Decode()
	return w.records
}

func wireFragment(side int, wire []byte, at int64) *core.StreamData {
	dir := reassembly.TCPDirClientToServer
	if side == 1 {
		dir = reassembly.TCPDirServerToClient
	}
	return &core.StreamData{Dir: dir, RawData: wire, CaptureInformation: gopacket.CaptureInfo{Timestamp: time.Unix(at, 123)}}
}

func TestRound2InitialUnknownPairsObservableTransactions(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		for _, separateMarker := range []bool{false, true} {
			request := wireFragment(0, []byte("GET /a HTTP/1.1\r\nHost: fixture.test\r\n\r\nHEAD /b HTTP/1.1\r\nHost: fixture.test\r\n\r\n"), 10)
			response := wireFragment(1, []byte("HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\naHTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n"), 11)
			data := core.DataFragments{request, response}
			request.SkippedBytes = -1
			if separateMarker {
				request.SkippedBytes = 0
				data = append(core.DataFragments{&core.StreamData{SkippedBytes: -1}}, data...)
			}
			if reverse {
				for _, f := range data {
					d := f.(*core.StreamData)
					d.Dir = !d.Dir
				}
			}
			records := captureHTTP(t, data)
			if len(records) != 2 {
				t.Fatalf("reverse=%v marker=%v: %v", reverse, separateMarker, records)
			}
			for _, r := range records {
				if r.Method == "" || r.StatusCode != 200 || r.ReassemblyStatus != "unknown-initial-stream-loss" || r.Timestamp != time.Unix(10, 123).UnixNano() || r.CommunityID != "1:fixture" {
					t.Fatal(r)
				}
			}
		}
	}
}

func TestRound2MalformedRequestsKeepEvidenceAndBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name, line, headers, body, target, issue string
		unsafe                                   bool
	}{
		{"http-chunked", "POST /qlik HTTP/1.1", "Transfer-Encoding: ,\tchunked,\r\n", "0\r\n\r\nGET /smuggled HTTP/1.1\r\n\r\n", "/qlik", "ambiguous-transfer-encoding", true},
		{"http-multiple-cl", "POST /cl HTTP/1.1", "Content-Length: 0\r\nContent-Length: 40\r\n", "GET /smuggled HTTP/1.1\r\n\r\n", "/cl", "ambiguous-content-length", true},
		{"equal-cl", "POST /cl HTTP/1.1", "Content-Length: 1\r\nContent-Length: 1\r\n", "x", "/cl", "duplicate-content-length", false},
		{"te-cl", "POST /te-cl HTTP/1.1", "Transfer-Encoding: chunked\r\nContent-Length: 0\r\n", "GET /smuggled HTTP/1.1\r\n\r\n", "/te-cl", "transfer-encoding-with-content-length", true},
		{"http-uri-spaces", "GET /uri afterspace HTTP/1.1", "", "", "/uri afterspace", "request-target-whitespace", false},
		{"detect-pcre-04", "GET  /  HTTP/1.1", "", "", "/", "nonstandard-request-line-spacing", false},
		{"detect-pcre-05", "GET  /test  HTTP/1.1", "", "", "/test", "nonstandard-request-line-spacing", false},
		{"http-missing-protocol", "GET /gen.php?hwid=synthetic", "", "", "/gen.php?hwid=synthetic", "missing-http-version", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire := tc.line + "\r\nHost: fixture.test\r\nX-Order: first\r\nx-order: second\r\n" + tc.headers + "\r\n" + tc.body
			if !tc.unsafe {
				wire += "GET /next HTTP/1.1\r\nHost: fixture.test\r\n\r\n"
			}
			if !Decoder.CanDecode([]byte(wire), nil) {
				t.Fatal("not selected")
			}
			for split := 1; split < len(wire); split++ {
				records := captureHTTP(t, core.DataFragments{wireFragment(0, []byte(wire[:split]), 10), wireFragment(0, []byte(wire[split:]), 11)})
				want := 2
				if tc.unsafe {
					want = 1
				}
				if len(records) != want {
					t.Fatalf("split=%d: %v", split, records)
				}
				r := records[0]
				if r.URL != tc.target || !strings.Contains(strings.Join(r.ParseQualifications, ","), tc.issue) || string(r.RawRequestLine) != tc.line+"\r\n" || len(r.RequestHeaders) < 3 || string(r.RequestHeaders[2].Raw) != "x-order: second\r\n" {
					t.Fatal(r)
				}
				if tc.unsafe && len(r.RequestBody) != 0 {
					t.Fatal("ambiguous bytes retained as a body", r)
				}
				if !tc.unsafe && records[1].URL != "/next" {
					t.Fatal("lost next request", records)
				}
			}
		})
	}
}

func TestRound2AmbiguousResponseAndInvalidChunkStopDirection(t *testing.T) {
	for _, wire := range []string{
		"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Length: 100\r\n\r\nHTTP/1.1 299 Fake\r\n\r\n",
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nNOT-HEX\r\nHTTP/1.1 299 Fake\r\n\r\n",
	} {
		records := captureHTTP(t, core.DataFragments{wireFragment(1, []byte(wire), 10)})
		if len(records) != 1 || records[0].StatusCode != 200 || records[0].ReassemblyStatus == "" {
			t.Fatal(records)
		}
	}
}

func TestRound2GapAndDiscardNeverJoinBody(t *testing.T) {
	for _, skipped := range []int{-1, 12, 0} {
		first := wireFragment(0, []byte("POST /partial HTTP/1.1\r\nContent-Length: 40\r\n\r\na"), 10)
		second := wireFragment(0, []byte("GET /observed HTTP/1.1\r\nHost: test\r\n\r\n"), 11)
		second.SkippedBytes = skipped
		if skipped == 0 {
			second.DiscardedBytes = 12
		}
		records := captureHTTP(t, core.DataFragments{first, second, wireFragment(1, []byte("HTTP/1.1 204 No Content\r\n\r\n"), 12)})
		if len(records) != 3 {
			t.Fatal(records)
		}
		for _, r := range records {
			if r.Method != "" && r.StatusCode != 0 {
				t.Fatal("paired across internal hole", r)
			}
		}
		if !bytes.Equal(records[1].RequestBody, []byte("a")) || !strings.Contains(records[1].ReassemblyStatus, "incomplete_request_body") {
			t.Fatal(records)
		}
	}
}

func TestRound2HeaderBudgetsStopBeforeUntrustedBody(t *testing.T) {
	for name, headers := range map[string]string{
		"count": strings.Repeat("X-Small: x\r\n", maxHTTPHeaderCount+1),
		"bytes": strings.Repeat("X-Padded: "+strings.Repeat("x", 1000)+"\r\n", 70),
		"line":  "X-Large: " + strings.Repeat("x", maxHTTPHeaders) + "\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			wire := "POST /bounded HTTP/1.1\r\n" + headers + "\r\nGET /fake HTTP/1.1\r\n\r\n"
			records := captureHTTP(t, core.DataFragments{wireFragment(0, []byte(wire), 10)})
			if len(records) != 1 || records[0].URL != "/bounded" || !strings.Contains(records[0].ReassemblyStatus, "http-header-limit") || len(records[0].RequestBody) != 0 {
				t.Fatal(records)
			}
		})
	}
}

func TestRound2NonHTTPMissingVersionNegative(t *testing.T) {
	for _, wire := range []string{"GET random text\r\n\r\n", "GET /target has no version\r\n\r\n", "POSTGRES /something\r\n\r\n"} {
		if Decoder.CanDecode([]byte(wire), nil) {
			t.Fatalf("selected non-HTTP %q", wire)
		}
		if records := captureHTTP(t, core.DataFragments{wireFragment(0, []byte(wire), 10)}); len(records) != 0 {
			t.Fatal(records)
		}
	}
}

func FuzzHTTPWireEvidence(f *testing.F) {
	for _, wire := range []string{"GET / HTTP/1.1\r\n\r\n", "POST / HTTP/1.1\r\nTransfer-Encoding: ,chunked,\r\n\r\n", "GET /no-version\r\n\r\n"} {
		f.Add([]byte(wire))
	}
	f.Fuzz(func(t *testing.T, wire []byte) {
		if len(wire) > maxHTTPHeaders*2 {
			t.Skip()
		}
		records := captureHTTP(t, core.DataFragments{wireFragment(0, wire, 10)})
		for _, r := range records {
			if len(r.RequestHeaders) > maxHTTPHeaderCount {
				t.Fatal(fmt.Sprint(r))
			}
		}
	})
}
