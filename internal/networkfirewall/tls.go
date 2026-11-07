package networkfirewall

import (
	"encoding/binary"
	"fmt"
	"time"
)

// TLSMetadata describes only the visible ClientHello. ECH can hide the real SNI.
type TLSMetadata struct {
	ServerName    string
	ALPN          []string
	LegacyVersion uint16
}

const helloMaxFlows = 1024
const helloMaxBytes = 65536
const helloIdle = 10 * time.Second

type helloFlow struct {
	start    uint32
	bytes    []byte
	last     time.Time
	metadata *TLSMetadata
}
type helloInspector struct{ flows map[string]*helloFlow }

func newHelloInspector() *helloInspector { return &helloInspector{flows: make(map[string]*helloFlow)} }

// observe is called serially by the NFQUEUE callback. Out-of-order, conflicting
// retransmissions and resource exhaustion abandon metadata, never invent a name.
func (h *helloInspector) observe(raw []byte, e PacketEvent, now time.Time) *TLSMetadata {
	for key, f := range h.flows {
		if now.Sub(f.last) > helloIdle {
			delete(h.flows, key)
		}
	}
	off := int(raw[0]&15) * 4
	if e.IPVersion == 6 {
		off = 40
		next := raw[6]
		for next != 6 {
			n := (int(raw[off+1]) + 1) * 8
			if next == 51 {
				n = (int(raw[off+1]) + 2) * 4
			}
			next = raw[off]
			off += n
		}
	}
	seq := binary.BigEndian.Uint32(raw[off+4 : off+8])
	if e.TCPFlags&2 != 0 {
		seq++
	}
	payload := raw[off+int(raw[off+12]>>4)*4:]
	key := fmt.Sprintf("%s:%d>%s:%d", e.SrcIP, e.SrcPort, e.DstIP, e.DstPort)
	if e.TCPFlags&2 != 0 {
		delete(h.flows, key)
	}
	f := h.flows[key]
	if e.TCPFlags&5 != 0 {
		delete(h.flows, key)
		return nil
	}
	if f != nil {
		f.last = now
		if f.metadata != nil {
			return cloneTLS(f.metadata)
		}
	}
	if len(payload) == 0 {
		return nil
	}
	if f == nil {
		if payload[0] != 22 || len(h.flows) >= helloMaxFlows {
			return nil
		}
		f = &helloFlow{start: seq, last: now}
		h.flows[key] = f
	}
	delta := int(int32(seq - f.start))
	if delta < 0 || delta > len(f.bytes) || delta+len(payload) > helloMaxBytes {
		delete(h.flows, key)
		return nil
	}
	overlap := len(f.bytes) - delta
	if overlap > len(payload) {
		overlap = len(payload)
	}
	for i := 0; i < overlap; i++ {
		if f.bytes[delta+i] != payload[i] {
			delete(h.flows, key)
			return nil
		}
	}
	f.bytes = append(f.bytes, payload[overlap:]...)
	metadata, invalid := parseHelloRecords(f.bytes)
	if invalid {
		delete(h.flows, key)
		return nil
	}
	if metadata != nil {
		f.metadata = metadata
		f.bytes = nil
		return cloneTLS(metadata)
	}
	return nil
}

func cloneTLS(m *TLSMetadata) *TLSMetadata {
	c := *m
	c.ALPN = append([]string(nil), m.ALPN...)
	return &c
}

func parseHelloRecords(b []byte) (*TLSMetadata, bool) {
	var handshake []byte
	for len(b) >= 5 {
		if b[0] != 22 || b[1] != 3 {
			return nil, true
		}
		n := int(binary.BigEndian.Uint16(b[3:5]))
		if n == 0 || n > 18432 {
			return nil, true
		}
		if len(b) < 5+n {
			return nil, false
		}
		handshake = append(handshake, b[5:5+n]...)
		b = b[5+n:]
		if len(handshake) < 4 {
			continue
		}
		if handshake[0] != 1 {
			return nil, true
		}
		size := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
		if size > helloMaxBytes-4 {
			return nil, true
		}
		if len(handshake) >= size+4 {
			m, ok := parseClientHello(handshake[4 : 4+size])
			return m, !ok
		}
	}
	return nil, false
}

type helloReader struct {
	b   []byte
	bad bool
}

func (r *helloReader) take(n int) []byte {
	if n < 0 || n > len(r.b) {
		r.bad = true
		return nil
	}
	b := r.b[:n]
	r.b = r.b[n:]
	return b
}
func (r *helloReader) byte() int {
	b := r.take(1)
	if len(b) == 0 {
		return 0
	}
	return int(b[0])
}
func (r *helloReader) uint16() int {
	b := r.take(2)
	if len(b) < 2 {
		return 0
	}
	return int(binary.BigEndian.Uint16(b))
}

func parseClientHello(b []byte) (*TLSMetadata, bool) {
	r := helloReader{b: b}
	version := r.uint16()
	r.take(32)
	r.take(r.byte())
	ciphers := r.uint16()
	if ciphers < 2 || ciphers%2 != 0 {
		return nil, false
	}
	r.take(ciphers)
	compression := r.byte()
	if compression < 1 {
		return nil, false
	}
	r.take(compression)
	m := &TLSMetadata{LegacyVersion: uint16(version)}
	if r.bad {
		return nil, false
	}
	if len(r.b) == 0 {
		return m, true
	}
	n := r.uint16()
	if n != len(r.b) {
		return nil, false
	}
	seen := make(map[int]bool)
	for len(r.b) > 0 && !r.bad {
		typ := r.uint16()
		n := r.uint16()
		ext := r.take(n)
		if seen[typ] {
			return nil, false
		}
		seen[typ] = true
		x := helloReader{b: ext}
		switch typ {
		case 0:
			if x.uint16() != len(x.b) {
				return nil, false
			}
			for len(x.b) > 0 && !x.bad {
				kind := x.byte()
				name := x.take(x.uint16())
				if kind == 0 {
					if len(name) == 0 || len(name) > 253 || m.ServerName != "" {
						return nil, false
					}
					for _, v := range name {
						if !((v >= 'a' && v <= 'z') || (v >= 'A' && v <= 'Z') || (v >= '0' && v <= '9') || v == '.' || v == '-') {
							return nil, false
						}
					}
					m.ServerName = string(name)
				}
			}
		case 16:
			if x.uint16() != len(x.b) {
				return nil, false
			}
			for len(x.b) > 0 && !x.bad {
				n := x.byte()
				if n == 0 {
					return nil, false
				}
				protocol := x.take(n)
				m.ALPN = append(m.ALPN, string(protocol))
			}
		}
		if x.bad {
			return nil, false
		}
	}
	return m, !r.bad
}
