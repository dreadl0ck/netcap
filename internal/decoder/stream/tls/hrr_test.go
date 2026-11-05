package tls

import (
	"encoding/hex"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/dreadl0ck/netcap/types"
	"testing"
)

func TestHelloRetryCompatibilityCCS(t *testing.T) {
	h, _ := recordTestSetup(t)
	old, count := ClientHelloDecoder.Writer, ClientHelloDecoder.NumRecordsWritten
	t.Cleanup(func() { ClientHelloDecoder.Writer, ClientHelloDecoder.NumRecordsWritten = old, count })
	for _, version := range []uint16{0x303, 0x304} {
		w := &helloWriter{}
		ClientHelloDecoder.Writer = w
		h.tls13 = false
		client := &tlsRecordFramer{reader: h, dir: reassembly.TCPDirClientToServer, emit: func(*types.TLSRecord) {}}
		server := &tlsRecordFramer{reader: h, dir: reassembly.TCPDirServerToClient, emit: func(*types.TLSRecord) {}}
		body := append([]byte{3, 3}, make([]byte, 32)...)
		body = append(body, 0, 0, 2, 0x13, 1, 1, 0, 0, 0)
		wire := recordWire(22, append([]byte{1, 0, 0, byte(len(body))}, body...))
		client.feed(wire, 1)
		random, _ := hex.DecodeString("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")
		sbody := append([]byte{3, 3}, random...)
		sbody = append(sbody, 0, 0x13, 1, 0, 0, 6, 0, 43, 0, 2, byte(version>>8), byte(version))
		server.feed(recordWire(22, append([]byte{2, 0, 0, byte(len(sbody))}, sbody...)), 2)
		client.feed(append(recordWire(20, []byte{1}), wire...), 3)
		want := 1
		if version == 0x304 {
			want = 2
		}
		if len(w.messages) != want {
			t.Fatalf("negotiated %x: %d hellos want %d", version, len(w.messages), want)
		}
	}
}
