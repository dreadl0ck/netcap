package http

import (
	"fmt"
	"github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"unsafe"
)

func TestDetachedEvidenceQueryDoesNotRetainInput(t *testing.T) {
	raw := "label=fixture" + strings.Repeat("&", 64<<10)
	values, err := decodeEvidenceQuery(raw, true)
	if err != nil || len(values) != 1 || values.Get("label") != "fixture" {
		t.Fatalf("unexpected decoded fields: %v, %v", values, err)
	}
	for name, field := range values {
		if unsafe.StringData(name) == unsafe.StringData(raw) || unsafe.StringData(field[0]) == unsafe.StringData(raw[len("label="):]) {
			t.Fatal("a retained field aliases the form input")
		}
	}
}

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

func TestMultipartRepeatedFieldsAtPartLimit(t *testing.T) {
	for _, n := range []int{1024, 1025} {
		var body strings.Builder
		for i := range n {
			fmt.Fprintf(&body, "--fixture\r\nContent-Disposition: form-data; name=\"tag\"\r\n\r\n%d\r\n", i)
		}
		body.WriteString("--fixture--\r\n")
		req := &http.Request{Method: "POST", URL: &url.URL{RawQuery: "tag=query"}, Header: http.Header{"Content-Type": {"multipart/form-data; boundary=fixture"}}}
		err := parseEvidenceForm(req, []byte(body.String()))
		if (err != nil) != (n > 1024) {
			t.Fatalf("%d parts: %v", n, err)
		}
		values := req.Form["tag"]
		if len(req.PostForm["tag"]) != 1024 || len(values) != 1025 || values[1024] != "query" {
			t.Fatal("lost accepted fields or query value", n)
		}
		for i := range 1024 {
			if values[i] != fmt.Sprint(i) {
				t.Fatalf("unexpected field %d: %s", i, values[i])
			}
		}
	}
}
