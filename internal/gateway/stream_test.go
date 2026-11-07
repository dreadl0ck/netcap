package gateway

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/policy"
)

type wireOrigin struct {
	listener net.Listener
	mu       sync.Mutex
	wire     [][]byte
	done     chan struct{}
}

func fixtureOrigin(t *testing.T, handler func(net.Conn, *wireOrigin)) *wireOrigin {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	o := &wireOrigin{listener: l, done: make(chan struct{})}
	go func() {
		defer close(o.done)
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(4 * time.Second))
		handler(c, o)
	}()
	t.Cleanup(func() {
		l.Close()
		select {
		case <-o.done:
		case <-time.After(5 * time.Second):
			t.Error("origin stuck")
		}
	})
	return o
}
func (o *wireOrigin) record(b []byte) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.wire = append(o.wire, append([]byte(nil), b...))
}
func (o *wireOrigin) snapshot() []byte {
	o.mu.Lock()
	defer o.mu.Unlock()
	return bytes.Join(o.wire, nil)
}
func (o *wireOrigin) wait(t *testing.T) {
	t.Helper()
	select {
	case <-o.done:
	case <-time.After(5 * time.Second):
		t.Fatal("origin not closed")
	}
}
func respCommand(args ...string) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "*%d\r\n", len(args))
	for _, a := range args {
		fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(a), a)
	}
	return b.Bytes()
}
func denyMethod(method string) Evaluator {
	return evaluateFunc(func(e policy.Event) (policy.Decision, error) {
		v := "allow"
		if e.Method == method {
			v = "deny"
		}
		return policy.Decision{Verdict: v}, nil
	})
}

func compileGatewayPolicy(t *testing.T, expression string) Evaluator {
	t.Helper()
	p, err := policy.Compile(policy.Bundle{Version: "1", ID: "gateway", Mode: "enforce", Default: "allow", Rules: []policy.Rule{{ID: "block", Action: "deny", Expression: expression}}})
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func writeSplit(t *testing.T, c net.Conn, b []byte) {
	t.Helper()
	for _, v := range b {
		if _, err := c.Write([]byte{v}); err != nil {
			t.Fatal(err)
		}
	}
}
func wantRESP(t *testing.T, r *bufio.Reader, want string) {
	t.Helper()
	b, err := readRESP(r, 1<<20, 0)
	if err != nil || string(b) != want {
		t.Fatalf("reply %q err %v, want %q", b, err, want)
	}
}

func TestRedisPipelineBinaryAndPreOriginDenial(t *testing.T) {
	o := fixtureOrigin(t, func(c net.Conn, o *wireOrigin) {
		r := bufio.NewReader(c)
		for {
			b, e := readRESP(r, 1<<20, 0)
			if e != nil {
				return
			}
			o.record(b)
			c.Write([]byte("+OK\r\n"))
		}
	})
	c, _, _ := startTCPGateway(t, Config{Protocol: "redis", Upstream: o.listener.Addr().String()}, compileGatewayPolicy(t, `Protocol == "redis" && Attributes["db.scope"] == "server"`))
	r := bufio.NewReader(c)
	first := respCommand("SET", "binary", "a\x00\r\nb")
	writeSplit(t, c, first)
	wantRESP(t, r, "+OK\r\n")
	c.Write(append(respCommand("GET", "binary"), respCommand("FLUSHALL")...))
	wantRESP(t, r, "+OK\r\n")
	wantRESP(t, r, "-NOPERM blocked by gateway\r\n")
	c.Close()
	o.wait(t)
	got := o.snapshot()
	if !bytes.Contains(got, []byte("a\x00\r\nb")) || bytes.Contains(got, []byte("FLUSHALL")) {
		t.Fatalf("wrong origin bytes %q", got)
	}
}
func TestRedisUnsupportedModesAndMalformedNeverDial(t *testing.T) {
	for _, b := range [][]byte{respCommand("MULTI"), respCommand("HELLO", "3"), respCommand("SUBSCRIBE", "x"), respCommand("CLIENT", "REPLY", "OFF"), []byte("*999999999\r\n"), []byte("*1\r\n$999999999\r\n"), []byte("PING\r\n")} {
		t.Run(fmt.Sprintf("%x", b[:min(12, len(b))]), func(t *testing.T) {
			o := fixtureOrigin(t, func(c net.Conn, o *wireOrigin) { o.record([]byte("connected")) })
			c, _, _ := startTCPGateway(t, Config{Protocol: "redis", Upstream: o.listener.Addr().String()}, allowAll())
			c.Write(b)
			io.ReadAll(c)
			if len(o.snapshot()) != 0 {
				t.Fatal("unsupported message reached origin")
			}
			o.listener.Close()
			o.wait(t)
		})
	}
}
func TestRedisSecretsNotInEvents(t *testing.T) {
	o := fixtureOrigin(t, func(c net.Conn, o *wireOrigin) {
		r := bufio.NewReader(c)
		for {
			if _, e := readRESP(r, 4096, 0); e != nil {
				return
			}
			c.Write([]byte("+OK\r\n"))
		}
	})
	events := make(chan policy.Event, 4)
	e := evaluateFunc(func(e policy.Event) (policy.Decision, error) {
		events <- e
		return policy.Decision{Verdict: "allow"}, nil
	})
	c, _, _ := startTCPGateway(t, Config{Protocol: "redis", Upstream: o.listener.Addr().String()}, e)
	c.Write(respCommand("AUTH", "user", "very-secret"))
	wantRESP(t, bufio.NewReader(c), "+OK\r\n")
	v := <-events
	if strings.Contains(fmt.Sprintf("%+v", v), "very-secret") {
		t.Fatal("AUTH credential exposed")
	}
	c.Close()
}

func startupPacket() []byte {
	b := append([]byte{0, 0, 0, 0, 0, 3, 0, 0}, []byte("user\x00tester\x00database\x00test\x00\x00")...)
	binary.BigEndian.PutUint32(b, uint32(len(b)))
	return b
}
func readPG(c net.Conn, startup bool) ([]byte, error) {
	h := make([]byte, 5)
	off := 1
	if startup {
		h = h[:4]
		off = 0
	}
	if _, err := io.ReadFull(c, h); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint32(h[off:]))
	if n < 4 || n > 1<<20 {
		return nil, errFrame
	}
	b := make([]byte, n-4)
	_, err := io.ReadFull(c, b)
	return append(h, b...), err
}
func pgReceive(t *testing.T, c net.Conn, kind byte) []byte {
	t.Helper()
	b, e := readPG(c, false)
	if e != nil || b[0] != kind {
		t.Fatalf("PG kind %c: %q %v", kind, b, e)
	}
	return b
}
func pgFixture(t *testing.T) *wireOrigin {
	return fixtureOrigin(t, func(c net.Conn, o *wireOrigin) {
		if b, e := readPG(c, true); e != nil {
			return
		} else {
			o.record(b)
		}
		c.Write(pgFrame('R', []byte{0, 0, 0, 3}))
		b, e := readPG(c, false)
		if e != nil || b[0] != 'p' {
			return
		}
		o.record(b)
		c.Write(append(pgFrame('R', []byte{0, 0, 0, 0}), pgFrame('Z', []byte{'I'})...))
		for {
			b, e = readPG(c, false)
			if e != nil {
				return
			}
			o.record(b)
			switch b[0] {
			case 'P':
				c.Write(pgFrame('1', nil))
			case 'B':
				c.Write(pgFrame('2', nil))
			case 'E':
				c.Write(pgFrame('C', []byte("SELECT 1\x00")))
			case 'S', 'Q':
				c.Write(pgFrame('Z', []byte{'I'}))
			case 'C':
				c.Write(pgFrame('3', nil))
			case 'X':
				return
			}
		}
	})
}
func pgLogin(t *testing.T, c net.Conn) {
	t.Helper()
	writeSplit(t, c, startupPacket())
	pgReceive(t, c, 'R')
	c.Write(pgFrame('p', []byte("very-secret\x00")))
	pgReceive(t, c, 'R')
	pgReceive(t, c, 'Z')
}
func eventAttrs(e policy.Event) map[string]string {
	return e.Attributes
}

func TestPostgresExtendedPipelineGateAndOpaqueAuth(t *testing.T) {
	o := pgFixture(t)
	events := make(chan policy.Event, 20)
	compiled := compileGatewayPolicy(t, `Protocol == "postgres" && Method == "EXECUTE" && Attributes["db.query"] == "DELETE FROM forbidden"`)
	p := evaluateFunc(func(e policy.Event) (policy.Decision, error) {
		events <- e
		return compiled.Evaluate(e)
	})
	c, _, _ := startTCPGateway(t, Config{Protocol: "postgres", Upstream: o.listener.Addr().String()}, p)
	pgLogin(t, c)
	parse := pgFrame('P', []byte("s\x00DELETE FROM forbidden\x00\x00\x00"))
	bind := pgFrame('B', []byte("p\x00s\x00\x00\x00\x00\x00\x00\x00"))
	execute := pgFrame('E', []byte{'p', 0, 0, 0, 0, 0})
	c.Write(bytes.Join([][]byte{parse, bind, execute, pgFrame('S', nil)}, nil))
	pgReceive(t, c, '1')
	pgReceive(t, c, '2')
	pgReceive(t, c, 'E')
	c.Close()
	o.wait(t)
	wire := o.snapshot()
	if !bytes.Contains(wire, parse) || !bytes.Contains(wire, bind) || bytes.Contains(wire, execute) {
		t.Fatalf("incorrect origin frame gating: %x", wire)
	}
	close(events)
	for e := range events {
		if strings.Contains(fmt.Sprintf("%+v", e), "very-secret") {
			t.Fatal("password exposed")
		}
		if e.Method == "EXECUTE" {
			if a := eventAttrs(e); a != nil && a["db.query"] != "DELETE FROM forbidden" {
				t.Fatalf("portal lost query: %+v", a)
			}
		}
	}
}
func TestPostgresSSLRejectAndSimpleQueryDeny(t *testing.T) {
	o := pgFixture(t)
	c, _, _ := startTCPGateway(t, Config{Protocol: "postgres", Upstream: o.listener.Addr().String()}, denyMethod("QUERY"))
	c.Write([]byte{0, 0, 0, 8, 4, 210, 22, 47})
	var b [1]byte
	if _, e := io.ReadFull(c, b[:]); e != nil || b[0] != 'N' {
		t.Fatal("SSLRequest not explicitly rejected")
	}
	pgLogin(t, c)
	denied := pgFrame('Q', []byte("DROP TABLE forbidden\x00"))
	writeSplit(t, c, denied)
	pgReceive(t, c, 'E')
	c.Close()
	o.wait(t)
	if bytes.Contains(o.snapshot(), denied) {
		t.Fatal("denied Query reached origin")
	}
}

func smtpFixture(t *testing.T) *wireOrigin {
	return fixtureOrigin(t, func(c net.Conn, o *wireOrigin) {
		c.Write([]byte("220 fixture\r\n"))
		r := bufio.NewReader(c)
		for {
			b, e := boundedLine(r, 4096)
			if e != nil {
				return
			}
			o.record(b)
			switch strings.Fields(string(b))[0] {
			case "EHLO":
				c.Write([]byte("250-fixture\r\n250-STARTTLS\r\n250 CHUNKING\r\n"))
			case "DATA":
				c.Write([]byte("354 go\r\n"))
				for {
					b, e = boundedLine(r, 4096)
					if e != nil {
						return
					}
					o.record(b)
					if bytes.Equal(b, []byte(".\r\n")) {
						break
					}
				}
				c.Write([]byte("250 queued\r\n"))
			case "QUIT":
				c.Write([]byte("221 bye\r\n"))
				return
			default:
				c.Write([]byte("250 ok\r\n"))
			}
		}
	})
}
func smtpResponse(t *testing.T, r *bufio.Reader, code string) string {
	t.Helper()
	var out string
	for {
		b, e := boundedLine(r, 4096)
		if e != nil {
			t.Fatal(e)
		}
		if string(b[:3]) != code {
			t.Fatalf("expected %s, got %q", code, b)
		}
		out += string(b)
		if b[3] == ' ' {
			return out
		}
	}
}
func smtpEnvelopeClient(t *testing.T, c net.Conn, r *bufio.Reader) {
	t.Helper()
	c.Write([]byte("MAIL FROM:<a@test>\r\nRCPT TO:<b@test>\r\nDATA\r\n"))
	smtpResponse(t, r, "250")
	smtpResponse(t, r, "250")
	smtpResponse(t, r, "354")
}
func TestSMTPWholeDataBeforeOriginAndResetRecovery(t *testing.T) {
	o := smtpFixture(t)
	p := compileGatewayPolicy(t, `Protocol == "smtp" && Attributes["mail.recipient"] == "b@test" && Body contains "forbidden"`)
	c, _, _ := startTCPGateway(t, Config{Protocol: "smtp", Upstream: o.listener.Addr().String()}, p)
	r := bufio.NewReader(c)
	smtpResponse(t, r, "220")
	writeSplit(t, c, []byte("EHLO client\r\n"))
	if s := smtpResponse(t, r, "250"); strings.Contains(s, "STARTTLS") || strings.Contains(s, "CHUNKING") {
		t.Fatalf("unsupported extension advertised: %s", s)
	}
	c.Write([]byte("STARTTLS\r\n"))
	smtpResponse(t, r, "502")
	smtpEnvelopeClient(t, c, r)
	c.Write([]byte("Subject: test\r\n\r\n"))
	time.Sleep(20 * time.Millisecond)
	if bytes.Contains(o.snapshot(), []byte("DATA\r\n")) {
		t.Fatal("DATA sent before entire body verdict")
	}
	writeSplit(t, c, []byte("forbidden at end\r\n.\r\n"))
	smtpResponse(t, r, "550")
	if b := o.snapshot(); bytes.Contains(b, []byte("DATA\r\n")) || bytes.Contains(b, []byte("forbidden")) || !bytes.Contains(b, []byte("RSET\r\n")) {
		t.Fatalf("denial leaked or failed reset: %q", b)
	}
	smtpEnvelopeClient(t, c, r)
	c.Write([]byte("Subject: good\r\n\r\n..dot-stuffed\r\n.\r\nQUIT\r\n"))
	smtpResponse(t, r, "250")
	smtpResponse(t, r, "221")
	c.Close()
	o.wait(t)
	b := o.snapshot()
	if bytes.Count(b, []byte("DATA\r\n")) != 1 || !bytes.Contains(b, []byte("..dot-stuffed\r\n")) || bytes.Contains(b, []byte("STARTTLS")) {
		t.Fatalf("wrong SMTP transcript %q", b)
	}
}

func TestDNSTCPPreOriginGateSplitCoalesced(t *testing.T) {
	o := fixtureOrigin(t, func(c net.Conn, o *wireOrigin) {
		for {
			var h [2]byte
			if _, e := io.ReadFull(c, h[:]); e != nil {
				return
			}
			b := make([]byte, word(h[:]))
			if _, e := io.ReadFull(c, b); e != nil {
				return
			}
			o.record(b)
			resp := dnsAnswer(b)
			c.Write(append([]byte{byte(len(resp) >> 8), byte(len(resp))}, resp...))
		}
	})
	p := evaluateFunc(func(e policy.Event) (policy.Decision, error) {
		v := "allow"
		if e.DNS.Name == "forbidden.test." {
			v = "deny"
		}
		return policy.Decision{Verdict: v}, nil
	})
	c, _, _ := startTCPGateway(t, Config{Protocol: "dns-tcp", Upstream: o.listener.Addr().String(), MaxDNSResponseBytes: 4096}, p)
	frame := func(b []byte) []byte { return append([]byte{byte(len(b) >> 8), byte(len(b))}, b...) }
	good := dnsRequest(t, "example.test.")
	bad := dnsRequest(t, "forbidden.test.")
	writeSplit(t, c, append(frame(good), frame(bad)...))
	for _, rcode := range []byte{0, 5} {
		var h [2]byte
		if _, e := io.ReadFull(c, h[:]); e != nil {
			t.Fatal(e)
		}
		b := make([]byte, word(h[:]))
		io.ReadFull(c, b)
		if b[3]&15 != rcode {
			t.Fatalf("DNS reply %x", b)
		}
	}
	c.Close()
	o.wait(t)
	if bytes.Contains(o.snapshot(), []byte("forbidden")) {
		t.Fatal("denied DNS question reached origin")
	}
}

func TestStreamCancellationClosesOrigins(t *testing.T) {
	for _, protocol := range []string{"redis", "postgres", "smtp", "dns-tcp", "mysql", "dnp3"} {
		t.Run(protocol, func(t *testing.T) {
			connected := make(chan struct{})
			closed := make(chan struct{})
			o := fixtureOrigin(t, func(c net.Conn, o *wireOrigin) { close(connected); io.Copy(io.Discard, c); close(closed) })
			c, cancel, _ := startTCPGateway(t, Config{Protocol: protocol, Upstream: o.listener.Addr().String()}, allowAll())
			switch protocol {
			case "redis":
				c.Write(respCommand("PING"))
			case "postgres":
				c.Write(startupPacket())
			case "dnp3":
				c.Write(dnpRequest(0xc0, 1, []byte{60, 2, 6}).wire())
			case "dns-tcp":
				b := dnsRequest(t, "example.test.")
				c.Write(append([]byte{byte(len(b) >> 8), byte(len(b))}, b...))
			}
			select {
			case <-connected:
			case <-time.After(time.Second):
				t.Fatal("no origin")
			}
			cancel()
			select {
			case <-closed:
			case <-time.After(time.Second):
				t.Fatal("upstream not closed on cancel")
			}
		})
	}
}

func TestRealRedis(t *testing.T) {
	addr := os.Getenv("GATEWAY_REDIS_ADDR")
	if addr == "" {
		t.Skip("set GATEWAY_REDIS_ADDR to an isolated real Redis")
	}
	key := fmt.Sprintf("gateway-test-%d", time.Now().UnixNano())
	c, _, _ := startTCPGateway(t, Config{Protocol: "redis", Upstream: addr}, denyMethod("DEL"))
	r := bufio.NewReader(c)
	c.Write(respCommand("SET", key, "a\x00\r\nb"))
	wantRESP(t, r, "+OK\r\n")
	c.Write(append(respCommand("GET", key), respCommand("DEL", key)...))
	wantRESP(t, r, "$5\r\na\x00\r\nb\r\n")
	wantRESP(t, r, "-NOPERM blocked by gateway\r\n")
	direct, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer direct.Close()
	direct.SetDeadline(time.Now().Add(time.Second))
	direct.Write(respCommand("GET", key))
	wantRESP(t, bufio.NewReader(direct), "$5\r\na\x00\r\nb\r\n")
	direct.Write(respCommand("DEL", key))
}

func FuzzRESPBounded(f *testing.F) {
	f.Add(respCommand("SET", "x", "a\x00\r\nb"))
	f.Add([]byte("*999999999\r\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 8192 {
			return
		}
		v, e := readRESP(bufio.NewReaderSize(bytes.NewReader(b), 4096), 4096, 0)
		if e == nil {
			if len(v) > 4096 {
				t.Fatal("size escaped")
			}
			if args, err := redisArgs(v); err == nil {
				redisIdentity(redisWord(args[0]), args, "default")
			}
		}
	})
}
func FuzzPostgresBounded(f *testing.F) {
	f.Add([]byte("s\x00SELECT 1\x00\x00\x00"))
	f.Add([]byte("p\x00s\x00\x00\x00\x00\x00\x00\x00"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 8192 {
			return
		}
		pgParse(b)
		pgBind(b)
		pgStartup(b)
	})
}

func FuzzSMTPDataBounded(f *testing.F) {
	f.Add([]byte("Subject: test\r\n\r\n..dot\r\n.\r\n"))
	f.Add([]byte(".\r\nMAIL FROM:<injected>\r\n"))
	f.Add([]byte("bad\rline\r\n.\r\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 8192 {
			return
		}
		wire, body, e := smtpData(bufio.NewReaderSize(bytes.NewReader(b), 4096), 4096)
		if e == nil && (len(wire) > 4096 || len(body) > len(wire) || !bytes.HasSuffix(wire, []byte(".\r\n"))) {
			t.Fatal("DATA framing escaped bounds")
		}
	})
}
