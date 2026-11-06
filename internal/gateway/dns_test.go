package gateway

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/policy"
	"golang.org/x/net/dns/dnsmessage"
)

func dnsRequest(t testing.TB, name string) []byte {
	t.Helper()
	n, err := dnsmessage.NewName(name)
	if err != nil {
		t.Fatal(err)
	}
	m := dnsmessage.Message{Header: dnsmessage.Header{ID: 0x1234, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
	b, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Build a compressed A answer independently of gateway parsing.
func dnsAnswer(req []byte) []byte {
	r := append([]byte(nil), req...)
	r[2], r[3] = 0x81, 0x80
	r[6], r[7] = 0, 1
	return append(r, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 192, 0, 2, 1)
}

type dnsOrigin struct {
	pc       net.PacketConn
	requests atomic.Int32
	done     chan struct{}
}

func startDNSOrigin(t *testing.T, response func([]byte) []byte) *dnsOrigin {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	o := &dnsOrigin{pc: pc, done: make(chan struct{})}
	go func() {
		defer close(o.done)
		buf := make([]byte, 4096)
		for {
			n, a, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			o.requests.Add(1)
			if r := response(buf[:n]); r != nil {
				_, _ = pc.WriteTo(r, a)
			}
		}
	}()
	t.Cleanup(func() { _ = pc.Close(); <-o.done })
	return o
}

func startDNSGateway(t *testing.T, cfg Config, p Evaluator) net.Conn {
	t.Helper()
	g, err := New(cfg, p)
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- g.ServePacket(ctx, pc) }()
	c, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = c.Close()
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(time.Second):
			t.Error("DNS gateway did not drain")
		}
	})
	return c
}

func exchangeDNS(t *testing.T, c net.Conn, b []byte) []byte {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	if _, err := c.Write(b); err != nil {
		t.Fatal(err)
	}
	r := make([]byte, 4096)
	n, err := c.Read(r)
	if err != nil {
		t.Fatal(err)
	}
	return r[:n]
}

func TestDNSOriginEnforcementAndCompressedResponse(t *testing.T) {
	o := startDNSOrigin(t, dnsAnswer)
	p, err := policy.Compile(policy.Bundle{Version: "1", ID: "dns", Mode: "enforce", Default: "deny", Rules: []policy.Rule{
		{ID: "allow-example", Action: "allow", Expression: "Protocol == 'dns' && DNS.Name == 'example.test.' && DNS.Type == 1"},
		{ID: "allow-response", Phase: "response", Action: "allow", Expression: "Protocol == 'dns' && DNS.Name == 'example.test.'"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	c := startDNSGateway(t, Config{Protocol: "dns", Upstream: o.pc.LocalAddr().String()}, p)
	r := exchangeDNS(t, c, dnsRequest(t, "denied.test."))
	if r[3]&15 != 5 || o.requests.Load() != 0 {
		t.Fatalf("denied query reached origin: %x count=%d", r, o.requests.Load())
	}
	req := dnsRequest(t, "EXAMPLE.test.")
	r = exchangeDNS(t, c, req)
	var msg dnsmessage.Message
	if err := msg.Unpack(r); err != nil {
		t.Fatal(err)
	}
	if msg.ID != 0x1234 || len(msg.Answers) != 1 || o.requests.Load() != 1 {
		t.Fatalf("allowed query response=%+v count=%d", msg, o.requests.Load())
	}
	if a, ok := msg.Answers[0].Body.(*dnsmessage.AResource); !ok || a.A != [4]byte{192, 0, 2, 1} {
		t.Fatalf("wrong answer %+v", msg.Answers)
	}
}

func TestDNSMalformedAndSourceDeniedNeverReachOrigin(t *testing.T) {
	for _, kind := range []string{"short", "response", "opcode", "multi-question", "any", "trailing", "compression-loop", "oversize", "source"} {
		t.Run(kind, func(t *testing.T) {
			o := startDNSOrigin(t, dnsAnswer)
			cfg := Config{Protocol: "dns", Upstream: o.pc.LocalAddr().String()}
			if kind == "source" {
				cfg.AllowedClients = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
			}
			c := startDNSGateway(t, cfg, allowAll())
			b := dnsRequest(t, "example.test.")
			switch kind {
			case "short":
				b = b[:10]
			case "response":
				b[2] |= 0x80
			case "opcode":
				b[2] |= 0x28
			case "multi-question":
				b[5] = 2
			case "any":
				b[len(b)-3] = 255
			case "trailing":
				b = append(b, 0)
			case "compression-loop":
				b = append(b[:12], 0xc0, 12, 0, 1, 0, 1)
			case "oversize":
				b = append(b, make([]byte, 513)...)
			}
			_ = c.SetDeadline(time.Now().Add(40 * time.Millisecond))
			if _, err := c.Write(b); err != nil {
				t.Fatal(err)
			}
			var r [512]byte
			if _, err := c.Read(r[:]); err == nil {
				t.Fatal("invalid/source-denied query received reply")
			}
			if o.requests.Load() != 0 {
				t.Fatal("invalid/source-denied query reached origin")
			}
		})
	}
}

func TestDNSResponseValidationAndAmplification(t *testing.T) {
	for _, kind := range []string{"id", "question", "opcode", "trailing", "bad-pointer", "amplification", "oversize", "timeout"} {
		t.Run(kind, func(t *testing.T) {
			o := startDNSOrigin(t, func(q []byte) []byte {
				r := dnsAnswer(q)
				switch kind {
				case "id":
					r[1]++
				case "question":
					r[13] = 'z'
				case "opcode":
					r[2] |= 8
				case "trailing":
					r = append(r, 0)
				case "bad-pointer":
					r[len(q)+1] = byte(len(q))
				case "amplification":
					r = append([]byte(nil), q...)
					r[2], r[3] = 0x81, 0x80
					r[7] = 1
					r = append(r, 0xc0, 12, 0, 16, 0, 1, 0, 0, 0, 1, 0, 201, 200)
					r = append(r, make([]byte, 200)...)
				case "oversize":
					r = append(r, make([]byte, 513-len(r))...)
				case "timeout":
					return nil
				}
				return r
			})
			c := startDNSGateway(t, Config{Protocol: "dns", Upstream: o.pc.LocalAddr().String(), IOTimeout: 40 * time.Millisecond}, allowAll())
			q := dnsRequest(t, "example.test.")
			r := exchangeDNS(t, c, q)
			if len(r) > 3*len(q) || binary.BigEndian.Uint16(r) != 0x1234 {
				t.Fatalf("unbounded/mismatched reply %x", r)
			}
			if kind == "amplification" || kind == "oversize" {
				if r[2]&2 == 0 {
					t.Fatal("oversize response not truncated")
				}
			} else if r[3]&15 != 2 {
				t.Fatalf("invalid upstream response not SERVFAIL: %x", r)
			}
		})
	}
}

func TestDNSCancellationDuringUpstreamWait(t *testing.T) {
	seen := make(chan struct{}, 1)
	o := startDNSOrigin(t, func([]byte) []byte { seen <- struct{}{}; return nil })
	g, err := New(Config{Protocol: "dns", Upstream: o.pc.LocalAddr().String()}, allowAll())
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- g.ServePacket(ctx, pc) }()
	c, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = c.Write(dnsRequest(t, "example.test."))
	select {
	case <-seen:
	case <-time.After(time.Second):
		t.Fatal("origin not queried")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("upstream wait blocked drain")
	}
}

func FuzzDNSQuery(f *testing.F) {
	f.Add(dnsRequest(f, "example.test."))
	f.Add([]byte{0, 1, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := parseDNSQuery(b)
		if err == nil && (len(m.Name) > 255 || len(b) > maxDNSQuery || m.Type == 255) {
			t.Fatal("invalid accepted DNS query")
		}
	})
}
