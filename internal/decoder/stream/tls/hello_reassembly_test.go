package tls

import (
	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
	"testing"
)

type helloWriter struct {
	netio.AuditRecordWriter
	messages []proto.Message
}

func (w *helloWriter) Write(m proto.Message) error {
	w.messages = append(w.messages, proto.Clone(m))
	return nil
}

func TestClientHelloEveryTCPAndRecordBoundary(t *testing.T) {
	h, _ := recordTestSetup(t)
	old, count := ClientHelloDecoder.Writer, ClientHelloDecoder.NumRecordsWritten
	t.Cleanup(func() { ClientHelloDecoder.Writer, ClientHelloDecoder.NumRecordsWritten = old, count })
	// TLS 1.2 ClientHello: random, empty session id, one cipher, null compression.
	body := append([]byte{3, 3}, make([]byte, 32)...)
	body = append(body, 0, 0, 2, 0xc0, 0x2f, 1, 0, 0, 0)
	message := append([]byte{1, 0, 0, byte(len(body))}, body...)
	for recordSplit := 1; recordSplit < len(message); recordSplit++ {
		wire := append(recordWire(22, message[:recordSplit]), recordWire(22, message[recordSplit:])...)
		for split := 1; split < len(wire); split++ {
			w := &helloWriter{}
			ClientHelloDecoder.Writer = w
			f := &tlsRecordFramer{reader: h, emit: func(_ *types.TLSRecord) {}}
			f.feed(wire[:split], 123)
			f.feed(wire[split:], 456)
			f.eof()
			if len(w.messages) != 1 {
				t.Fatalf("record %d TCP %d: %d hellos", recordSplit, split, len(w.messages))
			}
			r := w.messages[0].(*types.TLSClientHello)
			if r.Timestamp != 123 || r.SrcIP != "192.0.2.1" || r.Ja4 == "" || r.CommunityID != "community" {
				t.Fatal(r)
			}
		}
	}
	for cut := 1; cut < len(message); cut++ {
		w := &helloWriter{}
		ClientHelloDecoder.Writer = w
		f := &tlsRecordFramer{reader: h, emit: func(_ *types.TLSRecord) {}}
		f.feed(recordWire(22, message[:cut]), 1)
		f.gap(1, 2)
		f.feed(recordWire(22, message[cut:]), 3)
		f.eof()
		if len(w.messages) != 0 {
			t.Fatal("hello synthesized across capture gap")
		}
	}
}
