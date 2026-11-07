package tls

import (
	"bytes"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gopacket/gopacket"
)

func legacyHello(server, three bool, version uint16) []byte {
	var body []byte
	if server {
		body = []byte{4, 1, 0, 0, 2, 0, 0, 0, 6, 0, 16}
	} else {
		body = []byte{1, byte(version >> 8), byte(version), 0, 6, 0, 0, 0, 16}
	}
	body = append(body, 1, 0, 0x80, 0, 0, 0x2f)
	body = append(body, bytes.Repeat([]byte{0xab}, 16)...)
	if three {
		body = append(body, 0, 0, 0, 0)
		return append([]byte{byte(len(body) >> 8), byte(len(body)), 4}, body...)
	}
	return append([]byte{0x80 | byte(len(body)>>8), byte(len(body))}, body...)
}

func helloTestWriters(t *testing.T) (*tlsReader, *helloWriter, *helloWriter) {
	t.Helper()
	h, _ := recordTestSetup(t)
	cw, sw, cn, sn := ClientHelloDecoder.Writer, ServerHelloDecoder.Writer, ClientHelloDecoder.NumRecordsWritten, ServerHelloDecoder.NumRecordsWritten
	t.Cleanup(func() {
		ClientHelloDecoder.Writer, ServerHelloDecoder.Writer = cw, sw
		ClientHelloDecoder.NumRecordsWritten, ServerHelloDecoder.NumRecordsWritten = cn, sn
	})
	c, s := &helloWriter{}, &helloWriter{}
	ClientHelloDecoder.Writer, ServerHelloDecoder.Writer = c, s
	return h, c, s
}

func fragment(b []byte, server bool, ts int64) *core.StreamData {
	d := &core.StreamData{RawData: b, CaptureInformation: gopacket.CaptureInfo{Timestamp: time.Unix(0, ts)}}
	if server {
		d.Dir = reassembly.TCPDirServerToClient
	}
	return d
}

func TestSSLv2FramingAndMetadata(t *testing.T) {
	h, cw, sw := helloTestWriters(t)
	for _, three := range []bool{false, true} {
		for _, version := range []uint16{2, 0x303} {
			client, server := legacyHello(false, three, version), legacyHello(true, three, 2)
			if !Decoder.CanDecode(client, nil) || !Decoder.CanDecode(nil, server) {
				t.Fatal("legacy hello not selected")
			}
			for split := 1; split < len(client); split++ {
				cw.messages, sw.messages = nil, nil
				c := *h.conversation
				c.Data = core.DataFragments{fragment(client[:split], false, 123), fragment(client[split:], false, 456), fragment(append(server, server...), true, 789)}
				(&tlsReader{conversation: &c}).frameConversation()
				if len(cw.messages) != 1 || len(sw.messages) != 2 {
					t.Fatalf("three=%v version=%x split=%d: %d/%d", three, version, split, len(cw.messages), len(sw.messages))
				}
				r := cw.messages[0].(*types.TLSClientHello)
				if r.HelloFormat != "SSLv2" || r.HandshakeVersion != int32(version) || r.Timestamp != 123 || r.SrcIP != c.ClientIP || r.CommunityID != c.CommunityID || !bytes.Equal(r.SSLv2Challenge, bytes.Repeat([]byte{0xab}, 16)) || len(r.SSLv2CipherSpecs) != 2 || r.SSLv2CipherSpecs[0] != 0x010080 || r.SSLv2CipherSpecs[1] != 0x2f || len(r.CipherSuites) != 0 || len(r.Random) != 0 || r.Ja4 != "" {
					t.Fatalf("client: %+v", r)
				}
				for _, msg := range sw.messages {
					r := msg.(*types.TLSServerHello)
					if r.Version != 2 || r.Timestamp != 789 || r.SrcIP != c.ServerIP || r.HelloFormat != "SSLv2" || !r.SSLv2SessionIDHit || len(r.SSLv2ConnectionID) != 16 || r.SSLv2CipherSpecs[0] != 0x010080 || r.CipherSuite != 0 || r.Ja4S != "" {
						t.Fatalf("server: %+v", r)
					}
				}
			}
		}
	}
}

func TestSSLv2MalformedAndGaps(t *testing.T) {
	h, cw, _ := helloTestWriters(t)
	valid := legacyHello(false, false, 2)
	for _, mutate := range []func([]byte){
		func(b []byte) { b[0] = 0xff; b[1] = 0xff },
		func(b []byte) { b[5] = 1 },   // inconsistent cipher length
		func(b []byte) { b[10] = 15 }, // short challenge
		func(b []byte) { b[4] = 4 },   // unsupported version
		func(b []byte) { b[8] = 1 },   // invalid session id size
	} {
		b := bytes.Clone(valid)
		mutate(b)
		cw.messages = nil
		f := &sslv2Framer{reader: h}
		f.feed(b, 1)
		f.eof()
		if len(cw.messages) != 0 {
			t.Fatal("malformed SSLv2 accepted")
		}
	}
	for split := 1; split < len(valid); split++ {
		cw.messages = nil
		f := &sslv2Framer{reader: h}
		f.feed(valid[:split], 1)
		f.gap(1, 2)
		f.feed(valid[split:], 3)
		f.feed(valid, 4)
		f.eof()
		if len(cw.messages) != 0 {
			t.Fatal("SSLv2 fabricated across loss")
		}
	}
	cw.messages = nil
	f := &sslv2Framer{reader: h}
	f.gap(-1, 1)
	f.feed(valid, 2)
	if len(cw.messages) != 1 || cw.messages[0].(*types.TLSClientHello).ReassemblyStatus != "unknown-initial-stream-loss" {
		t.Fatal("missing initial qualifier")
	}
	for _, header := range [][]byte{{0x40, 20, 0}, {0, 20, 21}, {0x80, 0}} {
		if _, _, _, ok := sslv2Header(header); ok {
			t.Fatal("invalid SSLv2 header accepted", header)
		}
	}
}

func TestSSLv2CompatibleClientTLSReply(t *testing.T) {
	h, cw, sw := helloTestWriters(t)
	body := append([]byte{3, 3}, make([]byte, 32)...)
	body = append(body, 0, 0, 0x2f, 0, 0, 0)
	server := recordWire(22, append([]byte{2, 0, 0, byte(len(body))}, body...))
	c := *h.conversation
	c.Data = core.DataFragments{fragment(legacyHello(false, false, 0x303), true, 1), fragment(server, false, 2)}
	(&tlsReader{conversation: &c}).frameConversation()
	if len(cw.messages) != 1 || len(sw.messages) != 1 || cw.messages[0].(*types.TLSClientHello).SrcIP != c.ServerIP || sw.messages[0].(*types.TLSServerHello).Version != 0x303 || sw.messages[0].(*types.TLSServerHello).HelloFormat != "TLS" {
		t.Fatalf("mixed framing/role: %v %v", cw.messages, sw.messages)
	}
}

func FuzzSSLv2Framing(f *testing.F) {
	f.Add(legacyHello(false, false, 2), uint16(1))
	f.Add(legacyHello(true, true, 2), uint16(5))
	f.Add([]byte{0, 0, 0}, uint16(2))
	f.Fuzz(func(t *testing.T, b []byte, cut uint16) {
		if len(b) > 65536 {
			return
		}
		h := &tlsReader{conversation: &core.ConversationInfo{}}
		fr := &sslv2Framer{reader: h}
		n := min(int(cut), len(b))
		fr.feed(b[:n], 1)
		fr.feed(b[n:], 2)
		if len(fr.buf) > 32770 {
			t.Fatal("unbounded SSLv2 record")
		}
		fr.eof()
		_ = sslv2HelloType(b)
	})
}
