package gateway

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/policy"
)

func TestSMTPAuthOpaqueNegotiation(t *testing.T) {
	o := fixtureOrigin(t, func(c net.Conn, o *wireOrigin) {
		r := bufio.NewReader(c)
		c.Write([]byte("220 auth fixture\r\n"))
		line, e := boundedLine(r, 1000)
		if e != nil {
			return
		}
		o.record(line)
		c.Write([]byte("250 AUTH LOGIN\r\n"))
		line, e = boundedLine(r, 1000)
		if e != nil {
			return
		}
		o.record(line)
		c.Write([]byte("334 VXNlcm5hbWU6\r\n"))
		line, e = boundedLine(r, 1000)
		if e != nil {
			return
		}
		o.record(line)
		c.Write([]byte("334 UGFzc3dvcmQ6\r\n"))
		line, e = boundedLine(r, 1000)
		if e != nil {
			return
		}
		o.record(line)
		c.Write([]byte("235 authenticated\r\n"))
		io.Copy(io.Discard, c)
	})
	events := make(chan policy.Event, 4)
	p := evaluateFunc(func(e policy.Event) (policy.Decision, error) {
		events <- e
		return policy.Decision{Verdict: "allow"}, nil
	})
	c, _, _ := startTCPGateway(t, Config{Protocol: "smtp", Upstream: o.listener.Addr().String()}, p)
	r := bufio.NewReader(c)
	smtpResponse(t, r, "220")
	c.Write([]byte("EHLO test\r\n"))
	smtpResponse(t, r, "250")
	c.Write([]byte("AUTH LOGIN\r\n"))
	smtpResponse(t, r, "334")
	c.Write([]byte("dXNlcg==\r\n"))
	smtpResponse(t, r, "334")
	c.Write([]byte("dmVyeS1zZWNyZXQ=\r\n"))
	smtpResponse(t, r, "235")
	c.Close()
	o.wait(t)
	close(events)
	for e := range events {
		if v := fmt.Sprintf("%+v", e); strings.Contains(v, "dmVyeS1zZWNyZXQ=") || strings.Contains(v, "dXNlcg==") {
			t.Fatal("AUTH exchange exposed to policy")
		}
	}
	if !bytes.Contains(o.snapshot(), []byte("dmVyeS1zZWNyZXQ=\r\n")) {
		t.Fatal("opaque authentication did not progress")
	}
}

func TestPostgresSCRAMOpaqueNegotiation(t *testing.T) {
	// The fixture checks framing/progress, not the cryptography of SCRAM proofs.
	o := fixtureOrigin(t, func(c net.Conn, o *wireOrigin) {
		if _, e := readPG(c, true); e != nil {
			return
		}
		c.Write(pgFrame('R', append([]byte{0, 0, 0, 10}, []byte("SCRAM-SHA-256\x00\x00")...)))
		b, e := readPG(c, false)
		if e != nil || b[0] != 'p' {
			return
		}
		o.record(b)
		c.Write(pgFrame('R', append([]byte{0, 0, 0, 11}, []byte("server-first")...)))
		b, e = readPG(c, false)
		if e != nil || b[0] != 'p' {
			return
		}
		o.record(b)
		c.Write(bytes.Join([][]byte{pgFrame('R', append([]byte{0, 0, 0, 12}, []byte("server-final")...)), pgFrame('R', []byte{0, 0, 0, 0}), pgFrame('Z', []byte{'I'})}, nil))
		io.Copy(io.Discard, c)
	})
	events := make(chan policy.Event, 4)
	p := evaluateFunc(func(e policy.Event) (policy.Decision, error) {
		events <- e
		return policy.Decision{Verdict: "allow"}, nil
	})
	c, _, _ := startTCPGateway(t, Config{Protocol: "postgres", Upstream: o.listener.Addr().String()}, p)
	c.Write(startupPacket())
	pgReceive(t, c, 'R')
	c.Write(pgFrame('p', []byte("opaque-secret-first")))
	pgReceive(t, c, 'R')
	c.Write(pgFrame('p', []byte("opaque-secret-final")))
	pgReceive(t, c, 'R')
	pgReceive(t, c, 'R')
	pgReceive(t, c, 'Z')
	c.Close()
	o.wait(t)
	close(events)
	for e := range events {
		if strings.Contains(fmt.Sprintf("%+v", e), "opaque-secret") {
			t.Fatal("SCRAM exchange exposed")
		}
	}
}

func TestMessageLimitsAndProtocolInjectionNeverReachOrigin(t *testing.T) {
	cases := []struct {
		protocol string
		wire     []byte
	}{
		{"redis", respCommand("SET", "key", strings.Repeat("x", 600))},
		{"postgres", append([]byte{0, 0, 2, 89}, make([]byte, 600)...)},
	}
	for _, tt := range cases {
		t.Run(tt.protocol, func(t *testing.T) {
			o := fixtureOrigin(t, func(c net.Conn, o *wireOrigin) { o.record([]byte("connected")) })
			c, _, _ := startTCPGateway(t, Config{Protocol: tt.protocol, Upstream: o.listener.Addr().String(), MaxMessageBytes: 512}, allowAll())
			c.Write(tt.wire)
			io.ReadAll(c)
			if len(o.snapshot()) != 0 {
				t.Fatal("oversized message reached origin")
			}
			o.listener.Close()
			o.wait(t)
		})
	}
	o := smtpFixture(t)
	c, _, _ := startTCPGateway(t, Config{Protocol: "smtp", Upstream: o.listener.Addr().String(), MaxMessageBytes: 512}, allowAll())
	r := bufio.NewReader(c)
	smtpResponse(t, r, "220")
	c.Write([]byte("EHLO test\r\n"))
	smtpResponse(t, r, "250")
	smtpEnvelopeClient(t, c, r)
	c.Write([]byte(strings.Repeat("x", 600) + "\r\n.\r\n"))
	io.ReadAll(c)
	c.Close()
	o.wait(t)
	if bytes.Contains(o.snapshot(), []byte("DATA\r\n")) {
		t.Fatal("oversized DATA crossed origin gate")
	}
}

func TestPostgresParseDenialAndMalformedBind(t *testing.T) {
	for _, malformed := range []bool{false, true} {
		t.Run(fmt.Sprint(malformed), func(t *testing.T) {
			o := pgFixture(t)
			p := allowAll()
			if !malformed {
				p = denyMethod("PARSE")
			}
			c, _, _ := startTCPGateway(t, Config{Protocol: "postgres", Upstream: o.listener.Addr().String()}, p)
			pgLogin(t, c)
			denied := pgFrame('P', []byte("s\x00DELETE forbidden\x00\x00\x00"))
			if malformed {
				denied = pgFrame('B', []byte("p\x00s\x00\xff\xff"))
			}
			c.Write(denied)
			io.ReadAll(c)
			c.Close()
			o.wait(t)
			if bytes.Contains(o.snapshot(), denied) {
				t.Fatal("invalid/denied extended message reached origin")
			}
		})
	}
}

func TestGlobalSlotsAcrossListeners(t *testing.T) {
	connected := make(chan struct{})
	o := fixtureOrigin(t, func(c net.Conn, o *wireOrigin) { close(connected); io.Copy(io.Discard, c) })
	g, err := New(Config{Protocol: "redis", Upstream: o.listener.Addr().String(), MaxConnections: 1}, allowAll())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	start := func() net.Listener {
		l, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		done := make(chan error, 1)
		go func() { done <- g.Serve(ctx, l) }()
		t.Cleanup(func() {
			cancel()
			select {
			case e := <-done:
				if e != nil {
					t.Error(e)
				}
			case <-time.After(time.Second):
				t.Error("listener did not drain")
			}
		})
		return l
	}
	first, second := start(), start()
	c, err := net.Dial("tcp", first.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write(respCommand("PING"))
	select {
	case <-connected:
	case <-time.After(time.Second):
		t.Fatal("no first origin")
	}
	excess, err := net.Dial("tcp", second.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer excess.Close()
	excess.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, err = excess.Read(b[:]); err == nil {
		t.Fatal("global connection limit bypassed")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("global excess connection queued")
	}
	cancel()
	o.wait(t)
}

func TestRedisSessionMessageLimit(t *testing.T) {
	o := fixtureOrigin(t, func(c net.Conn, o *wireOrigin) {
		r := bufio.NewReader(c)
		for {
			b, e := readRESP(r, 4096, 0)
			if e != nil {
				return
			}
			o.record(b)
			c.Write([]byte("+PONG\r\n"))
		}
	})
	c, _, _ := startTCPGateway(t, Config{Protocol: "redis", Upstream: o.listener.Addr().String(), MaxSessionMessages: 1}, allowAll())
	c.Write(append(respCommand("PING"), respCommand("FLUSHALL")...))
	wantRESP(t, bufio.NewReader(c), "+PONG\r\n")
	io.ReadAll(c)
	c.Close()
	o.wait(t)
	if bytes.Contains(o.snapshot(), []byte("FLUSHALL")) {
		t.Fatal("session message limit failed")
	}
}
