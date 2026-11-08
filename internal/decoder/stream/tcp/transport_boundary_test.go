package tcp

import (
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	httpstream "github.com/dreadl0ck/netcap/internal/decoder/stream/http"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/imap"
	tlsstream "github.com/dreadl0ck/netcap/internal/decoder/stream/tls"
	"github.com/dreadl0ck/netcap/types"
)

func TestReorderedFINPayloadDefersClose(t *testing.T) {
	for _, queuedPostClose := range []bool{false, true} {
		name := "payload-only"
		if queuedPostClose {
			name = "queued-post-close"
		}
		t.Run(name, func(t *testing.T) {
			round2Config(t, imap.Decoder)
			r := newRound2Trace(143)
			r.send(false, 100, "S", "")
			r.send(true, 200, "SA", "")
			r.send(false, 101, "A", "")
			s := r.factory.streams[0]
			before := s.tcpstate.String()
			r.send(true, 301, "FA", strings.Repeat("b", 100))
			if s.tcpstate.String() != before {
				t.Fatal("future payload FIN changed lifecycle before the hole filled")
			}
			postclose := ""
			if queuedPostClose {
				postclose = "postclose"
				r.send(true, 402, "A", postclose)
			}
			r.send(true, 201, "A", strings.Repeat("a", 100))
			if s.tcpstate.String() == before {
				t.Fatal("contiguous FIN did not change lifecycle")
			}
			r.assembler.FlushAll()
			if got := string(s.server.DataSlice().Bytes()); got != strings.Repeat("a", 100)+strings.Repeat("b", 100)+postclose {
				t.Fatalf("reassembled bytes = %q", got)
			}
			for _, f := range s.server.DataSlice() {
				d := f.(*core.StreamData)
				if strings.Contains(string(d.Raw()), "a") || strings.Contains(string(d.Raw()), "b") {
					if d.TCPObservation != "" {
						t.Fatal("pre-FIN payload qualified as post-close")
					}
				}
				if string(d.Raw()) == "postclose" && d.TCPObservation != "after-fin" {
					t.Fatal("missing deferred FIN qualification")
				}
			}
		})
	}
}

func TestTCPHTTPPostCloseFraming(t *testing.T) {
	for _, closeFlag := range []string{"R", "FA"} {
		t.Run(closeFlag, func(t *testing.T) {
			w := round2Config(t, httpstream.Decoder)
			r := newRound2Trace(80)
			r.send(false, 100, "S", "")
			r.send(true, 200, "SA", "")
			r.send(false, 101, "A", "GET /fabricated")
			r.send(false, 116, closeFlag, "")
			seq := uint32(116)
			if closeFlag == "FA" {
				seq++
			}
			r.send(false, seq, "A", " HTTP/1.1\r\nHost: test\r\n\r\nGET /observed HTTP/1.1\r\nHost: test\r\n\r\n")
			r.assembler.FlushAll()
			if len(w.records) != 1 {
				t.Fatalf("HTTP observations: %v", w.records)
			}
			record := w.records[0].(*types.HTTP)
			if record.URL != "/observed" || !strings.Contains(record.ReassemblyStatus, "endpoint delivery unconfirmed") {
				t.Fatalf("fabricated or unqualified HTTP: %v", record)
			}
		})
	}
}

func TestTCPTLSPostCloseFraming(t *testing.T) {
	round2Config(t, tlsstream.Decoder)
	old, count := tlsstream.ClientHelloDecoder.Writer, tlsstream.ClientHelloDecoder.NumRecordsWritten
	t.Cleanup(func() {
		tlsstream.ClientHelloDecoder.Writer, tlsstream.ClientHelloDecoder.NumRecordsWritten = old, count
	})
	w := &round2Writer{}
	tlsstream.ClientHelloDecoder.Writer = w
	body := append([]byte{3, 3}, make([]byte, 32)...)
	body = append(body, 0, 0, 2, 0xc0, 0x2f, 1, 0, 0, 0)
	message := append([]byte{1, 0, 0, byte(len(body))}, body...)
	wire := append([]byte{22, 3, 3, 0, byte(len(message))}, message...)
	r := newRound2Trace(443)
	r.send(false, 100, "S", "")
	r.send(true, 200, "SA", "")
	r.send(false, 101, "A", string(wire[:20]))
	r.send(false, 121, "R", "")
	r.send(false, 121, "A", string(wire[20:]))
	r.assembler.FlushAll()
	if len(w.records) != 0 {
		t.Fatalf("TLS hello fabricated across RST: %v", w.records)
	}
	r = newRound2Trace(443)
	r.send(false, 100, "S", "")
	r.send(true, 200, "SA", "")
	r.send(false, 101, "A", "")
	r.send(false, 101, "R", "")
	r.send(false, 101, "A", string(wire))
	r.assembler.FlushAll()
	if len(w.records) != 1 || !strings.Contains(w.records[0].(*types.TLSClientHello).ReassemblyStatus, "after-rst; endpoint delivery unconfirmed") {
		t.Fatalf("missing standalone qualified TLS hello: %v", w.records)
	}
}
