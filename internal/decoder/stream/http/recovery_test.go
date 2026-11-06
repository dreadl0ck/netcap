package http

import (
	"fmt"
	"github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"testing"
)

func TestDirectionalHTTPRecoveryAndExactTargets(t *testing.T) {
	old, cfg, count := Decoder.Writer, config.Instance, Decoder.NumRecordsWritten
	t.Cleanup(func() { Decoder.Writer, config.Instance, Decoder.NumRecordsWritten = old, cfg, count })
	config.Instance = &config.Config{IncludePayloads: true}
	for _, reverse := range []bool{false, true} {
		w := &httpEvidenceWriter{}
		Decoder.Writer = w
		requestDir, responseDir := reassembly.TCPDirClientToServer, reassembly.TCPDirServerToClient
		if reverse {
			requestDir, responseDir = responseDir, requestDir
		}
		c := &core.ConversationInfo{ClientIP: "192.0.2.1", ServerIP: "192.0.2.2", ClientPort: 50000, ServerPort: 443, Data: core.DataFragments{
			&core.StreamData{Dir: requestDir, RawData: []byte("GET /44313,6048%2fX?q=a,b HTTP/1.1\r\nHost: example.test\r\nUser-Agent: test,raw\r\n\r\nGET /lost HTTP/1.1\r\nHost:")},
			&core.StreamData{Dir: responseDir, RawData: []byte("HTTP/1.1 204 No Content\r\n\r\n")},
			&core.StreamData{Dir: requestDir, SkippedBytes: 300, RawData: []byte("missing-tail\r\nGET /recovered HTTP/1.1\r\nHost: example.test\r\n\r\n")},
		}}
		(&httpReader{conversation: c}).Decode()
		requests := 0
		for _, r := range w.records {
			if r.Method == "" {
				continue
			}
			requests++
			if r.ReassemblyStatus == "" {
				t.Fatal("loss not qualified", r)
			}
			if r.URL != "/recovered" && (r.URL != "/44313,6048%2fX?q=a,b" || r.UserAgent != "test,raw") {
				t.Fatal(r)
			}
			want := c.ClientIP
			if reverse {
				want = c.ServerIP
			}
			if r.SrcIP != want {
				t.Fatal("wrong application direction", r)
			}
		}
		if requests != 2 {
			t.Fatalf("reverse %v: %v", reverse, w.records)
		}
	}
}

func TestHTTPBodyRequestTextIsNotResynchronized(t *testing.T) {
	old, cfg, count := Decoder.Writer, config.Instance, Decoder.NumRecordsWritten
	t.Cleanup(func() { Decoder.Writer, config.Instance, Decoder.NumRecordsWritten = old, cfg, count })
	config.Instance = &config.Config{}
	w := &httpEvidenceWriter{}
	Decoder.Writer = w
	body := "GET /not-a-request HTTP/1.1\r\n\r\n"
	wire := fmt.Sprintf("POST /body HTTP/1.1\r\nHost: example.test\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	(&httpReader{conversation: &core.ConversationInfo{Data: core.DataFragments{&core.StreamData{RawData: []byte(wire)}}}}).Decode()
	if len(w.records) != 1 || w.records[0].URL != "/body" {
		t.Fatal(w.records)
	}
}

func TestBackconnectHTTPAfterBinaryPreface(t *testing.T) {
	old, cfg, count := Decoder.Writer, config.Instance, Decoder.NumRecordsWritten
	t.Cleanup(func() { Decoder.Writer, config.Instance, Decoder.NumRecordsWritten = old, cfg, count })
	config.Instance = &config.Config{}
	request := []byte("control\r\n\x00\xaa\x00\x00GET /favicon.ico HTTP/1.1\r\nHost: example.test\r\n\r\n")
	response := []byte("client-id\r\nready\r\nHTTP/1.1 204 No Content\r\n\r\n")
	if !Decoder.CanDecode(response, request) {
		t.Fatal("paired HTTP after preface not recognized")
	}
	if Decoder.CanDecode(nil, request) {
		t.Fatal("unilateral embedded HTTP claimed")
	}
	w := &httpEvidenceWriter{}
	Decoder.Writer = w
	(&httpReader{conversation: &core.ConversationInfo{ClientIP: "192.0.2.1", ServerIP: "192.0.2.2", Data: core.DataFragments{&core.StreamData{RawData: request, Dir: reassembly.TCPDirServerToClient}, &core.StreamData{RawData: response, Dir: reassembly.TCPDirClientToServer}}}}).Decode()
	found := false
	for _, r := range w.records {
		if r.Method == "GET" {
			found = true
			if r.URL != "/favicon.ico" || r.SrcIP != "192.0.2.2" || r.ReassemblyStatus != "unpaired_after_protocol_preface" {
				t.Fatal(r)
			}
		}
	}
	if !found {
		t.Fatal("reverse request missing", w.records)
	}
}

func TestHTTPDoubleSlashOriginTarget(t *testing.T) {
	if !containsHTTPMethod([]byte("GET //MEIwQDA%2BMDww HTTP/1.1\r\n")) {
		t.Fatal("valid double-slash path treated as URL authority")
	}
}
