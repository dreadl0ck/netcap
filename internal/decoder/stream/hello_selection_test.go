package stream

import (
	"github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/tls"
	"testing"
)

func TestTLSHelloOnlySelectionAndSingleWriter(t *testing.T) {
	previous := config.Instance
	t.Cleanup(func() {
		config.Instance = previous
		tls.ClientHelloDecoder.Writer = nil
		tls.ServerHelloDecoder.Writer = nil
		tls.RecordDecoder.Writer = nil
		tls.Decoder.Writer = nil
	})
	for _, excluded := range []bool{false, true} {
		c := *config.DefaultConfig
		c.Out = t.TempDir()
		c.IncludeDecoders = "TLSClientHello"
		c.Null = true
		c.Proto = false
		c.Quiet = true
		if excluded {
			c.ExcludeDecoders = "TLSClientHello"
		}
		config.Instance = &c
		streams, err := InitDecoders(&c)
		if err != nil {
			t.Fatal(err)
		}
		abstract, err := InitAbstractDecoders(&c)
		if err != nil {
			t.Fatal(err)
		}
		body := append([]byte{3, 3}, make([]byte, 32)...)
		body = append(body, 0, 0, 2, 0xc0, 0x2f, 1, 0, 0, 0)
		wire := tlsRecord(22, append([]byte{1, 0, 0, byte(len(body))}, body...))
		fragments := core.DataFragments{&core.StreamData{RawData: wire[:2]}, &core.StreamData{RawData: wire[2:]}}
		conv := &core.ConversationInfo{Data: fragments, ClientData: fragments}
		sel, found := SelectDecoder(&SelectionInput{Transport: core.TCP, ServerPort: 443, PortClient: wire[:2], ScanClient: wire, Conversation: conv})
		if found == excluded {
			t.Fatalf("excluded %v: selected %v", excluded, sel)
		}
		if found {
			sel.Decoder.Decode()
			if tls.ClientHelloDecoder.NumRecordsWritten != 1 {
				t.Fatal("hello not emitted exactly once", tls.ClientHelloDecoder.NumRecordsWritten)
			}
		}
		for _, d := range streams {
			d.GetWriter().Close(0)
		}
		for _, d := range abstract {
			d.GetWriter().Close(0)
		}
	}
}

func TestSelectionDoesNotCopyDirectionsOnFastPath(t *testing.T) {
	matchingEnv(t)
	for _, port := range []int32{80, 64999} {
		calls := 0
		wire := []byte("GET / HTTP/1.1\r\nHost: fixture.test\r\n\r\n")
		sel, ok := SelectDecoder(&SelectionInput{Transport: core.TCP, ServerPort: port, PortClient: wire, Conversation: &core.ConversationInfo{}, ScanBytes: func() ([]byte, []byte) { calls++; return wire, nil }})
		if !ok || sel.Name != "HTTP" || port == 80 && calls != 0 || port != 80 && calls != 1 {
			t.Fatal(port, sel, calls)
		}
	}
}
