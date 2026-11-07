package gateway

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/policy"
)

func TestConfigAndClientBounds(t *testing.T) {
	base := Config{Protocol: "modbus", Upstream: "127.0.0.1:502"}
	for _, kind := range []string{"protocol", "upstream", "unspecified", "multicast", "workers", "idle", "io", "session", "dns-cap", "prefix", "nil-policy"} {
		t.Run(kind, func(t *testing.T) {
			cfg := base
			evaluator := allowAll()
			switch kind {
			case "protocol":
				cfg.Protocol = "tls"
			case "upstream":
				cfg.Upstream = "127.0.0.1:0"
			case "unspecified":
				cfg.Upstream = "0.0.0.0:502"
			case "multicast":
				cfg.Upstream = "224.0.0.1:502"
			case "workers":
				cfg.MaxConnections = 4097
			case "idle":
				cfg.IdleTimeout = -1
			case "io":
				cfg.IOTimeout = 2 * time.Minute
			case "session":
				cfg.SessionTimeout = -1
			case "dns-cap":
				cfg.MaxDNSResponseBytes = 65535
			case "prefix":
				cfg.AllowedClients = []netip.Prefix{{}}
			case "nil-policy":
				var p *policy.Compiled
				evaluator = p
			}
			if _, err := New(cfg, evaluator); err == nil {
				t.Fatal("invalid config accepted")
			}
		})
	}
	g, err := New(base, allowAll())
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"127.0.0.1", "::1", "::ffff:127.0.0.1"} {
		if _, ok := g.clientAllowed(&net.TCPAddr{IP: net.ParseIP(ip), Port: 1234}); !ok {
			t.Fatalf("loopback %s denied", ip)
		}
	}
	if _, ok := g.clientAllowed(&net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1234}); ok {
		t.Fatal("default exposed a public resolver/gateway")
	}
	base.AllowedClients = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	g, err = New(base, allowAll())
	if err != nil {
		t.Fatal(err)
	}
	base.AllowedClients[0] = netip.MustParsePrefix("0.0.0.0/0")
	if _, ok := g.clientAllowed(&net.TCPAddr{IP: net.ParseIP("198.51.100.1"), Port: 1234}); ok {
		t.Fatal("caller mutated gateway ACL")
	}
}

func TestPolicyFailureNeverReachesOrigins(t *testing.T) {
	failing := evaluateFunc(func(policy.Event) (policy.Decision, error) {
		return policy.Decision{Verdict: "allow"}, errors.New("capacity exhausted")
	})
	o := startModbusOrigin(t)
	c, _, _ := startTCPGateway(t, Config{Protocol: "modbus", Upstream: o.listener.Addr().String()}, failing)
	_, _ = c.Write(adu(1, 6, 0, 100, 0, 99))
	r, err := receiveADU(c)
	if err != nil {
		t.Fatal(err)
	}
	if r[7] != 0x86 || o.connections.Load() != 0 || o.register.Load() != 42 {
		t.Fatal("policy error failed open")
	}
	d := startDNSOrigin(t, dnsAnswer)
	udp := startDNSGateway(t, Config{Protocol: "dns", Upstream: d.pc.LocalAddr().String()}, failing)
	resp := exchangeDNS(t, udp, dnsRequest(t, "example.test."))
	if resp[3]&15 != 5 || d.requests.Load() != 0 {
		t.Fatal("DNS policy error failed open")
	}
}

func TestModbusConnectionLimitAndUpstreamCancellation(t *testing.T) {
	origin, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()
	seen := make(chan net.Conn, 1)
	go func() {
		c, err := origin.Accept()
		if err == nil {
			seen <- c
		}
	}()
	g, err := New(Config{Protocol: "modbus", Upstream: origin.Addr().String(), MaxConnections: 1}, allowAll())
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- g.Serve(ctx, l) }()
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = c.Write(adu(1, 3, 0, 0, 0, 1))
	var upstream net.Conn
	select {
	case upstream = <-seen:
	case <-time.After(time.Second):
		t.Fatal("origin did not receive connection")
	}
	defer upstream.Close()
	if _, err := receiveADU(upstream); err != nil {
		t.Fatal(err)
	}
	second, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	_ = second.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if n, err := second.Read(b[:]); n != 0 || err == nil {
		t.Fatal("excess connection not rejected")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("excess connection was queued")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("upstream response wait blocked shutdown")
	}
	_ = upstream.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := upstream.Read(b[:]); err == nil {
		t.Fatal("upstream socket leaked")
	}
}

func TestModbusSessionBoundsIdleConnection(t *testing.T) {
	c, _, _ := startTCPGateway(t, Config{Protocol: "modbus", Upstream: "127.0.0.1:1", SessionTimeout: 25 * time.Millisecond}, allowAll())
	var b [1]byte
	if n, err := c.Read(b[:]); n != 0 || err == nil {
		t.Fatal("session deadline did not close connection")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("session timeout was not enforced")
	}
}

func TestDNSWorkerLimit(t *testing.T) {
	seen := make(chan struct{}, 10)
	o := startDNSOrigin(t, func([]byte) []byte { seen <- struct{}{}; return nil })
	c := startDNSGateway(t, Config{Protocol: "dns", Upstream: o.pc.LocalAddr().String(), MaxConnections: 1, IOTimeout: 500 * time.Millisecond}, allowAll())
	q := dnsRequest(t, "example.test.")
	_, _ = c.Write(q)
	select {
	case <-seen:
	case <-time.After(time.Second):
		t.Fatal("origin not queried")
	}
	for i := 0; i < 8; i++ {
		_, _ = c.Write(q)
	}
	select {
	case <-seen:
		t.Fatal("worker limit allowed another upstream query")
	case <-time.After(50 * time.Millisecond):
	}
}

func TestModbusMaximumWriteQuantities(t *testing.T) {
	for _, function := range []byte{15, 16, 23} {
		t.Run(string(rune('A'+function)), func(t *testing.T) {
			max := 123
			if function == 15 {
				max = 1968
			}
			if function == 23 {
				max = 121
			}
			for _, quantity := range []int{max, max + 1} {
				p := []byte{function, 0, 0, byte(quantity >> 8), byte(quantity)}
				count := quantity * 2
				if function == 15 {
					count = (quantity + 7) / 8
				}
				if function == 23 {
					p = []byte{23, 0, 0, 0, 125, 0, 0, byte(quantity >> 8), byte(quantity)}
				}
				p = append(p, byte(count))
				p = append(p, make([]byte, count)...)
				m, err := parseModbusRequest(adu(1, p...))
				if (err == nil) != (quantity == max) {
					t.Fatalf("function=%d quantity=%d metadata=%+v err=%v", function, quantity, m, err)
				}
			}
		})
	}
}

func TestDNSCaseFoldingPreservesBinaryLabels(t *testing.T) {
	q := dnsRequest(t, "example.test.")
	q[13] = 0xff
	m, err := parseDNSQuery(q)
	if err != nil {
		t.Fatal(err)
	}
	if m.Name[0] != 0xff {
		t.Fatalf("binary label was changed: %x", m.Name)
	}
}
