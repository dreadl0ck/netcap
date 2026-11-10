package http

import (
	"fmt"
	"github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestMultipartFieldsAreExportedWithoutTemporaryFiles(t *testing.T) {
	old, cfg, count := Decoder.Writer, config.Instance, Decoder.NumRecordsWritten
	t.Cleanup(func() { Decoder.Writer, config.Instance, Decoder.NumRecordsWritten = old, cfg, count })
	config.Instance = &config.Config{}
	w := &httpEvidenceWriter{}
	Decoder.Writer = w
	body := "--fixture\r\nContent-Disposition: form-data; name=\"sysinfo\"\r\n\r\nName: OTHER-PC.example.test\r\n--fixture\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"ignored.txt\"\r\n\r\nnot a field\r\n--fixture--\r\n"
	wire := fmt.Sprintf("POST /inventory?sysinfo=query HTTP/1.1\r\nHost: fixture.test\r\nContent-Type: multipart/form-data; boundary=fixture\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	(&httpReader{conversation: &core.ConversationInfo{Data: core.DataFragments{&core.StreamData{RawData: []byte(wire)}}}}).Decode()
	if len(w.records) != 1 || w.records[0].Parameters["sysinfo"] != "Name: OTHER-PC.example.test query" || w.records[0].Parameters["upload"] != "" {
		t.Fatal(w.records)
	}
	for _, data := range []string{body[:len(body)-20], "--fixture\r\nContent-Disposition: form-data; name=\"huge\"\r\n\r\n" + strings.Repeat("x", 1<<20) + "\r\n--fixture--\r\n"} {
		req := &http.Request{Method: "POST", URL: &url.URL{}, Header: http.Header{"Content-Type": {"multipart/form-data; boundary=fixture"}}}
		if err := parseEvidenceForm(req, []byte(data)); err == nil {
			t.Fatal("corrupt or oversized multipart form accepted")
		}
	}
	w.records = nil
	wire = "POST /inventory HTTP/1.1\r\nHost: fixture.test\r\nContent-Type: multipart/form-data; boundary=fixture\r\nContent-Length: 3\r\n\r\nbad"
	(&httpReader{conversation: &core.ConversationInfo{Data: core.DataFragments{&core.StreamData{RawData: []byte(wire)}}}}).Decode()
	if len(w.records) != 1 || w.records[0].ReassemblyStatus != "" || !strings.Contains(strings.Join(w.records[0].ParseQualifications, ","), "incomplete-request-form") {
		t.Fatal("malformed form changed observed HTTP framing", w.records)
	}
}

func TestMalformedTargetAndSemicolonDoNotHideRequests(t *testing.T) {
	old, cfg, count := Decoder.Writer, config.Instance, Decoder.NumRecordsWritten
	t.Cleanup(func() { Decoder.Writer, config.Instance, Decoder.NumRecordsWritten = old, cfg, count })
	config.Instance = &config.Config{IncludePayloads: true}
	w := &httpEvidenceWriter{}
	Decoder.Writer = w
	wire := "POST /user_sync?a=left;right&b=x\x1fy HTTP/1.1\r\nHost: fixture.test\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 7\r\n\r\nx=a;b;cGET /next HTTP/1.1\r\nHost: fixture.test\r\n\r\n"
	if !Decoder.CanDecode([]byte(wire), nil) {
		t.Fatal("malformed target not recognized as HTTP evidence")
	}
	(&httpReader{conversation: &core.ConversationInfo{Data: core.DataFragments{&core.StreamData{RawData: []byte(wire)}}}}).Decode()
	if len(w.records) != 2 {
		t.Fatalf("lost pipeline boundary: %v", w.records)
	}
	r := w.records[0]
	if r.URL != "/user_sync?a=left;right&b=x\x1fy" || r.Parameters["a"] != "left;right" || r.Parameters["x"] != "a;b;c" || r.ReassemblyStatus != "invalid-request-target-control-byte" || w.records[1].URL != "/next" {
		t.Fatal(w.records)
	}
}
