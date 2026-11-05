package http

import (
	"github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"testing"
)

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
