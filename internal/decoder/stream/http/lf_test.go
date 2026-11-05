package http

import (
	"github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"testing"
)

func TestLFOnlyNetSupportRequestsRemainHTTP(t *testing.T) {
	old, cfg, count := Decoder.Writer, config.Instance, Decoder.NumRecordsWritten
	t.Cleanup(func() { Decoder.Writer, config.Instance, Decoder.NumRecordsWritten = old, cfg, count })
	config.Instance = &config.Config{}
	wire := []byte("POST http://example.test/fakeurl.htm HTTP/1.1\nHost: example.test\nUser-Agent: NetSupport Manager/1.3\nContent-Length: 2\n\nxx")
	if !Decoder.CanDecode(wire, nil) {
		t.Fatal("LF-only request not selected")
	}
	w := &httpEvidenceWriter{}
	Decoder.Writer = w
	(&httpReader{conversation: &core.ConversationInfo{Data: core.DataFragments{&core.StreamData{RawData: wire}}}}).Decode()
	if len(w.records) != 1 || w.records[0].URL != "http://example.test/fakeurl.htm" {
		t.Fatal(w.records)
	}
}
