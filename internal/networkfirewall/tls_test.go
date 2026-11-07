package networkfirewall

import (
	"encoding/binary"
	"testing"
	"time"
)

func helloFixture() []byte {
	name := []byte("example.test")
	sni := []byte{0, byte(len(name) + 3), 0, 0, byte(len(name))}
	sni = append(sni, name...)
	ext := []byte{0, 0, 0, byte(len(sni))}
	ext = append(ext, sni...)
	ext = append(ext, 0, 16, 0, 5, 0, 3, 2, 'h', '2')
	body := make([]byte, 34)
	body[0] = 3
	body[1] = 3
	body = append(body, 0, 0, 2, 0x13, 1, 1, 0, 0, byte(len(ext)))
	body = append(body, ext...)
	hs := []byte{1, 0, 0, byte(len(body))}
	hs = append(hs, body...)
	record := []byte{22, 3, 1, 0, byte(len(hs))}
	return append(record, hs...)
}

func tlsPacket(payload []byte, seq uint32) []byte {
	b := packet(false, 443)
	b = append(b, payload...)
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	binary.BigEndian.PutUint32(b[24:28], seq)
	b[33] = 0x18
	return b
}

func TestIncrementalVisibleHello(t *testing.T) {
	b := helloFixture()
	now := time.Now()
	for split := 1; split < len(b); split++ {
		h := newHelloInspector()
		raw := tlsPacket(b[:split], 100)
		e, _ := ParsePacket(raw)
		if m := h.observe(raw, e, now); m != nil {
			t.Fatalf("premature hello %d", split)
		}
		// Identical retransmissions must not advance the stream.
		h.observe(raw, e, now)
		raw = tlsPacket(b[split:], 100+uint32(split))
		e, _ = ParsePacket(raw)
		m := h.observe(raw, e, now)
		if m == nil || m.ServerName != "example.test" || len(m.ALPN) != 1 || m.ALPN[0] != "h2" {
			t.Fatalf("split %d: %+v", split, m)
		}
	}
	for n := 0; n < len(b); n++ {
		if m, _ := parseHelloRecords(b[:n]); m != nil {
			t.Fatalf("accepted truncation %d", n)
		}
	}
	h := newHelloInspector()
	raw := tlsPacket(b[:10], 100)
	e, _ := ParsePacket(raw)
	h.observe(raw, e, now)
	raw = tlsPacket(b[11:], 111)
	e, _ = ParsePacket(raw)
	if h.observe(raw, e, now) != nil || len(h.flows) != 0 {
		t.Fatal("out-of-order segment classified")
	}
	for i := 0; i < helloMaxFlows; i++ {
		h.flows[string(rune(i))] = &helloFlow{last: now}
	}
	raw = tlsPacket(b, 100)
	e, _ = ParsePacket(raw)
	if h.observe(raw, e, now) != nil {
		t.Fatal("flow cap ignored")
	}
	if h.observe(raw, e, now.Add(helloIdle+time.Second)) == nil {
		t.Fatal("expired flows not reclaimed")
	}
}

func FuzzVisibleHello(f *testing.F) {
	f.Add(helloFixture())
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) <= helloMaxBytes {
			_, _ = parseHelloRecords(b)
			_, _ = parseClientHello(b)
		}
	})
}
