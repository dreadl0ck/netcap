package gateway

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/dreadl0ck/netcap/internal/policy"
)

func mysqlFixtureRead(c net.Conn) (byte, []byte, error) {
	var h [4]byte
	if _, err := io.ReadFull(c, h[:]); err != nil {
		return 0, nil, err
	}
	n := int(h[0]) | int(h[1])<<8 | int(h[2])<<16
	if n > 1<<20 {
		return 0, nil, errFrame
	}
	b := make([]byte, n)
	_, err := io.ReadFull(c, b)
	return h[3], b, err
}
func mysqlFixtureGreeting(caps uint32) []byte {
	b := append([]byte{10}, []byte("8.4.8-fixture\x00")...)
	b = append(b, 1, 0, 0, 0)
	b = append(b, []byte("12345678")...)
	b = append(b, 0, byte(caps), byte(caps>>8), 45, 2, 0, byte(caps>>16), byte(caps>>24), 21)
	b = append(b, make([]byte, 10)...)
	b = append(b, []byte("abcdefghijkl\x00caching_sha2_password\x00")...)
	return b
}
func mysqlFixtureLogin(flags uint32, secret []byte) []byte {
	b := make([]byte, 32)
	binary.LittleEndian.PutUint32(b, flags)
	binary.LittleEndian.PutUint32(b[4:], 1<<20)
	b[8] = 45
	b = append(b, []byte("tester\x00")...)
	b = append(b, byte(len(secret)))
	b = append(b, secret...)
	if flags&8 != 0 {
		b = append(b, []byte("test\x00")...)
	}
	if flags&mysqlPlugin != 0 {
		b = append(b, []byte("caching_sha2_password\x00")...)
	}
	return b
}
func mysqlOK(status uint16) []byte  { return []byte{0, 0, 0, byte(status), byte(status >> 8), 0, 0} }
func mysqlEOF(status uint16) []byte { return []byte{0xfe, 0, 0, byte(status), byte(status >> 8)} }
func mysqlFixtureColumn() []byte {
	var b []byte
	for _, s := range []string{"def", "test", "t", "t", "v", "v"} {
		b = append(b, byte(len(s)))
		b = append(b, s...)
	}
	return append(b, 12, 45, 0, 11, 0, 0, 0, 3, 0, 0, 0, 0, 0)
}
func mysqlFixture(t *testing.T, split bool) (*wireOrigin, *atomic.Int32) {
	effects := new(atomic.Int32)
	o := fixtureOrigin(t, func(c net.Conn, o *wireOrigin) {
		c.Write(mysqlPacket(0, mysqlFixtureGreeting(mysqlCapabilities&^mysqlSSL)))
		seq, login, err := mysqlFixtureRead(c)
		if err != nil || seq != 1 {
			return
		}
		o.record(login)
		flags := binary.LittleEndian.Uint32(login)
		deprecate := flags&mysqlDeprecateEOF != 0
		c.Write(mysqlPacket(2, mysqlOK(2)))
		statements := map[uint32]string{}
		id := uint32(10)
		for {
			seq, p, err := mysqlFixtureRead(c)
			if err != nil || seq != 0 || len(p) == 0 {
				return
			}
			o.record(p)
			var responses [][]byte
			switch p[0] {
			case 1:
				return
			case 2, 14, 26:
				responses = [][]byte{mysqlOK(2)}
			case 3, 23:
				query := string(p[1:])
				binaryRows := false
				if p[0] == 23 {
					if len(p) < 10 {
						return
					}
					query = statements[binary.LittleEndian.Uint32(p[1:])]
					binaryRows = true
				}
				switch {
				case strings.HasPrefix(query, "INSERT"), strings.HasPrefix(query, "DROP"):
					effects.Add(1)
					responses = [][]byte{mysqlOK(2)}
				case query == "LOCAL":
					responses = [][]byte{append([]byte{0xfb}, []byte("/forbidden/file")...)}
				case query == "MULTI":
					responses = [][]byte{mysqlOK(10)}
				default:
					responses = [][]byte{{1}, mysqlFixtureColumn()}
					if !deprecate {
						responses = append(responses, mysqlEOF(2))
					}
					row := []byte{1, '7'}
					if query == "SELECT empty" {
						row = []byte{0}
					}
					if binaryRows {
						row = []byte{0, 0, 7, 0, 0, 0}
					}
					responses = append(responses, row)
					end := mysqlEOF(2)
					if deprecate {
						end = mysqlOK(2)
						end[0] = 0xfe
					}
					responses = append(responses, end)
				}
			case 22:
				query := string(p[1:])
				statements[id] = query
				columns, params := 0, strings.Count(query, "?")
				if strings.HasPrefix(query, "SELECT") {
					columns = 1
				}
				response := []byte{0, byte(id), byte(id >> 8), byte(id >> 16), byte(id >> 24), byte(columns), 0, byte(params), 0, 0, 0, 0}
				id++
				responses = [][]byte{response}
				for _, n := range []int{params, columns} {
					for i := 0; i < n; i++ {
						responses = append(responses, mysqlFixtureColumn())
					}
					if n > 0 && !deprecate {
						responses = append(responses, mysqlEOF(2))
					}
				}
			case 25:
				delete(statements, binary.LittleEndian.Uint32(p[1:]))
				continue
			default:
				return
			}
			var wire []byte
			for i, b := range responses {
				wire = append(wire, mysqlPacket(byte(i+1), b)...)
			}
			if split {
				for _, v := range wire {
					if _, err := c.Write([]byte{v}); err != nil {
						return
					}
				}
			} else {
				c.Write(wire)
			}
		}
	})
	return o, effects
}
func mysqlTestLogin(t *testing.T, c net.Conn, deprecate bool) {
	t.Helper()
	seq, greeting, err := mysqlFixtureRead(c)
	if err != nil || seq != 0 {
		t.Fatalf("greeting %d %v", seq, err)
	}
	_, _, _, caps, ok := mysqlGreeting(greeting)
	if !ok {
		t.Fatal("bad greeting")
	}
	flags := mysqlProtocol41 | mysqlSecure | mysqlPlugin | 8
	if deprecate {
		flags |= mysqlDeprecateEOF
	}
	if flags&^caps != 0 {
		t.Fatal("fixture capabilities unavailable")
	}
	c.Write(mysqlPacket(1, mysqlFixtureLogin(flags, []byte("opaque-secret"))))
	seq, p, err := mysqlFixtureRead(c)
	if err != nil || seq != 2 || len(p) == 0 || p[0] != 0 {
		t.Fatalf("login response %d %x %v", seq, p, err)
	}
}
func mysqlTestResult(t *testing.T, c net.Conn, deprecate, binaryRows bool) []byte {
	t.Helper()
	g, err := New(Config{Protocol: "mysql", Upstream: "127.0.0.1:1"}, allowAll())
	if err != nil {
		t.Fatal(err)
	}
	conv := mysqlConversation{g: g, ctx: t.Context(), c: c, seq: 1}
	if success, parseErr := conv.result(deprecate, binaryRows); parseErr != nil || !success {
		t.Fatalf("result failed: %v (%x)", parseErr, conv.wire)
	}
	return conv.wire
}
func TestMySQLQueryGateAndResultTerminators(t *testing.T) {
	for _, deprecate := range []bool{false, true} {
		t.Run(fmt.Sprint(deprecate), func(t *testing.T) {
			o, effects := mysqlFixture(t, !deprecate)
			p := compileGatewayPolicy(t, `Protocol == "mysql" && Attributes["db.query"] == "DROP forbidden"`)
			c, _, _ := startTCPGateway(t, Config{Protocol: "mysql", Upstream: o.listener.Addr().String()}, p)
			mysqlTestLogin(t, c, deprecate)
			writeSplit(t, c, mysqlPacket(0, append([]byte{3}, []byte("INSERT allowed")...)))
			mysqlTestResult(t, c, deprecate, false)
			// A text row beginning with 0x00 is an empty value, not an OK terminator.
			c.Write(bytes.Join([][]byte{mysqlPacket(0, append([]byte{3}, []byte("SELECT empty")...)), mysqlPacket(0, append([]byte{3}, []byte("DROP forbidden")...))}, nil))
			mysqlTestResult(t, c, deprecate, false)
			seq, b, err := mysqlFixtureRead(c)
			if err != nil || seq != 1 || b[0] != 0xff {
				t.Fatalf("denial: %d %x %v", seq, b, err)
			}
			c.Close()
			o.wait(t)
			if effects.Load() != 1 || bytes.Contains(o.snapshot(), []byte("DROP forbidden")) {
				t.Fatalf("forbidden query/effect crossed boundary: %d", effects.Load())
			}
		})
	}
}
func mysqlPrepareTest(t *testing.T, c net.Conn, query string, deprecate bool) (uint32, int) {
	t.Helper()
	c.Write(mysqlPacket(0, append([]byte{22}, []byte(query)...)))
	g, _ := New(Config{Protocol: "mysql", Upstream: "127.0.0.1:1"}, allowAll())
	conv := mysqlConversation{g: g, ctx: t.Context(), c: c, seq: 1}
	id, params, ok, err := conv.prepare(deprecate)
	if err != nil || !ok {
		t.Fatalf("prepare: %v %v", ok, err)
	}
	return id, params
}
func mysqlExecute(id uint32, params bool) []byte {
	b := []byte{23, byte(id), byte(id >> 8), byte(id >> 16), byte(id >> 24), 0, 1, 0, 0, 0}
	if params {
		b = append(b, 0, 1, 3, 0, 7, 0, 0, 0)
	}
	return b
}
func TestMySQLPreparedStatementIDQueryGate(t *testing.T) {
	for _, deprecate := range []bool{false, true} {
		t.Run(fmt.Sprint(deprecate), func(t *testing.T) {
			o, effects := mysqlFixture(t, false)
			p := compileGatewayPolicy(t, `Protocol == "mysql" && Method == "STMT_EXECUTE" && Attributes["db.query"] == "INSERT forbidden VALUES (?)"`)
			c, _, _ := startTCPGateway(t, Config{Protocol: "mysql", Upstream: o.listener.Addr().String()}, p)
			mysqlTestLogin(t, c, deprecate)
			id, params := mysqlPrepareTest(t, c, "SELECT ?", deprecate)
			if params != 1 {
				t.Fatal("lost parameter count")
			}
			c.Write(mysqlPacket(0, mysqlExecute(id, true)))
			mysqlTestResult(t, c, deprecate, true)
			id, _ = mysqlPrepareTest(t, c, "INSERT forbidden VALUES (?)", deprecate)
			execute := mysqlExecute(id, true)
			writeSplit(t, c, mysqlPacket(0, execute))
			_, b, err := mysqlFixtureRead(c)
			if err != nil || b[0] != 0xff {
				t.Fatal("missing Execute denial")
			}
			c.Close()
			o.wait(t)
			if effects.Load() != 0 || bytes.Contains(o.snapshot(), execute) {
				t.Fatal("denied binary Execute reached origin")
			}
		})
	}
}
func TestMySQLUnsupportedResponseModesClose(t *testing.T) {
	for _, query := range []string{"LOCAL", "MULTI"} {
		t.Run(query, func(t *testing.T) {
			o, _ := mysqlFixture(t, false)
			c, _, _ := startTCPGateway(t, Config{Protocol: "mysql", Upstream: o.listener.Addr().String()}, allowAll())
			mysqlTestLogin(t, c, true)
			c.Write(mysqlPacket(0, append([]byte{3}, []byte(query)...)))
			_, b, err := mysqlFixtureRead(c)
			if err != nil || b[0] != 0xff {
				t.Fatal("unsupported response not rejected")
			}
			c.Close()
			o.wait(t)
			if bytes.Contains(o.snapshot(), []byte("/forbidden/file")) {
				t.Fatal("file bytes sent upstream")
			}
		})
	}
}
func TestMySQLAuthSecretsAndSSLRejection(t *testing.T) {
	o, _ := mysqlFixture(t, false)
	events := make(chan policy.Event, 8)
	p := evaluateFunc(func(e policy.Event) (policy.Decision, error) {
		events <- e
		return policy.Decision{Verdict: "allow"}, nil
	})
	c, _, _ := startTCPGateway(t, Config{Protocol: "mysql", Upstream: o.listener.Addr().String()}, p)
	mysqlTestLogin(t, c, true)
	c.Write(mysqlPacket(0, []byte{1}))
	c.Close()
	o.wait(t)
	close(events)
	for e := range events {
		if strings.Contains(fmt.Sprintf("%+v", e), "opaque-secret") {
			t.Fatal("authentication bytes exposed")
		}
	}
	o2, _ := mysqlFixture(t, false)
	c2, _, _ := startTCPGateway(t, Config{Protocol: "mysql", Upstream: o2.listener.Addr().String()}, allowAll())
	_, greet, err := mysqlFixtureRead(c2)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, caps, _ := mysqlGreeting(greet)
	if caps&mysqlSSL != 0 {
		t.Fatal("unsupported TLS advertised")
	}
	ssl := make([]byte, 32)
	binary.LittleEndian.PutUint32(ssl, mysqlProtocol41|mysqlSSL|mysqlSecure)
	c2.Write(mysqlPacket(1, ssl))
	seq, b, err := mysqlFixtureRead(c2)
	if err != nil || seq != 2 || b[0] != 0xff {
		t.Fatal("SSLRequest not explicitly rejected")
	}
	c2.Close()
	o2.wait(t)
	if len(o2.snapshot()) != 0 {
		t.Fatal("SSLRequest leaked into upstream authentication")
	}
}
func TestMySQLNegotiatedTLSBothLegs(t *testing.T) {
	p := makePKI(t)
	o := fixtureOrigin(t, func(raw net.Conn, o *wireOrigin) {
		raw.Write(mysqlPacket(0, mysqlFixtureGreeting(mysqlCapabilities)))
		seq, ssl, e := mysqlFixtureRead(raw)
		if e != nil || seq != 1 || len(ssl) != 32 || binary.LittleEndian.Uint32(ssl)&mysqlSSL == 0 {
			return
		}
		c := tls.Server(raw, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{p.pair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: p.roots})
		if c.Handshake() != nil {
			return
		}
		seq, login, e := mysqlFixtureRead(c)
		if e != nil || seq != 2 {
			return
		}
		o.record(login)
		c.Write(mysqlPacket(3, mysqlOK(2)))
		seq, command, e := mysqlFixtureRead(c)
		if e != nil || seq != 0 {
			return
		}
		o.record(command)
		c.Write(mysqlPacket(1, mysqlOK(2)))
	})
	cfg := Config{Protocol: "mysql", Upstream: o.listener.Addr().String(), TLSCert: p.cert, TLSKey: p.key, ClientCA: p.ca, UpstreamTLS: true, UpstreamServerName: "localhost", UpstreamCA: p.ca, UpstreamCert: p.cert, UpstreamKey: p.key}
	raw, _, _ := startTCPGateway(t, cfg, allowAll())
	_, greeting, e := mysqlFixtureRead(raw)
	if e != nil {
		t.Fatal(e)
	}
	_, _, _, caps, _ := mysqlGreeting(greeting)
	if caps&mysqlSSL == 0 {
		t.Fatal("TLS unavailable")
	}
	flags := mysqlProtocol41 | mysqlSecure | mysqlPlugin | mysqlSSL
	ssl := make([]byte, 32)
	binary.LittleEndian.PutUint32(ssl, flags)
	ssl[8] = 45
	raw.Write(mysqlPacket(1, ssl))
	c := tls.Client(raw, p.client(true))
	if e = c.Handshake(); e != nil {
		t.Fatal(e)
	}
	c.Write(mysqlPacket(2, mysqlFixtureLogin(flags, []byte("opaque-secret"))))
	seq, b, e := mysqlFixtureRead(c)
	if e != nil || seq != 3 || b[0] != 0 {
		t.Fatalf("TLS auth %d %x %v", seq, b, e)
	}
	c.Write(mysqlPacket(0, []byte{14}))
	mysqlTestResult(t, c, false, false)
	c.Close()
	o.wait(t)
	if !bytes.Contains(o.snapshot(), []byte{14}) {
		t.Fatal("verified TLS did not progress")
	}
}
func TestMySQLSequenceMultipartAndLongDataRejected(t *testing.T) {
	for _, wire := range [][]byte{mysqlPacket(1, []byte{3, 'x'}), {0xff, 0xff, 0xff, 0}, {0, 0, 0, 0}, mysqlPacket(0, []byte{24, 1, 0, 0, 0, 0, 0, 'x'})} {
		t.Run(fmt.Sprintf("%x", wire[:min(len(wire), 8)]), func(t *testing.T) {
			o, _ := mysqlFixture(t, false)
			c, _, _ := startTCPGateway(t, Config{Protocol: "mysql", Upstream: o.listener.Addr().String()}, allowAll())
			mysqlTestLogin(t, c, true)
			before := len(o.snapshot())
			c.Write(wire)
			io.ReadAll(c)
			c.Close()
			o.wait(t)
			if len(o.snapshot()) != before {
				t.Fatal("unsupported command reached origin")
			}
		})
	}
}
func FuzzMySQLBounded(f *testing.F) {
	f.Add(mysqlFixtureGreeting(mysqlCapabilities))
	f.Add(mysqlFixtureLogin(mysqlProtocol41|mysqlSecure|mysqlPlugin|8, []byte("secret")))
	f.Add(mysqlFixtureColumn())
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 8192 {
			return
		}
		mysqlGreeting(b)
		mysqlLogin(b)
		mysqlLenenc(b)
		mysqlColumn(b)
		mysqlTextRow(b, 16)
		mysqlStatus(b, true)
		mysqlStatus(b, false)
	})
}

func TestMySQLAuthSwitchOpaqueSequence(t *testing.T) {
	o := fixtureOrigin(t, func(c net.Conn, o *wireOrigin) {
		c.Write(mysqlPacket(0, mysqlFixtureGreeting(mysqlCapabilities&^mysqlSSL)))
		if _, _, e := mysqlFixtureRead(c); e != nil {
			return
		}
		challenge := append([]byte{0xfe}, []byte("mysql_native_password\x0012345678901234567890\x00")...)
		c.Write(mysqlPacket(2, challenge))
		seq, b, e := mysqlFixtureRead(c)
		if e != nil || seq != 3 {
			return
		}
		o.record(b)
		c.Write(mysqlPacket(4, mysqlOK(2)))
		io.Copy(io.Discard, c)
	})
	events := make(chan policy.Event, 4)
	p := evaluateFunc(func(e policy.Event) (policy.Decision, error) {
		events <- e
		return policy.Decision{Verdict: "allow"}, nil
	})
	c, _, _ := startTCPGateway(t, Config{Protocol: "mysql", Upstream: o.listener.Addr().String()}, p)
	mysqlFixtureRead(c)
	flags := mysqlProtocol41 | mysqlSecure | mysqlPlugin
	c.Write(mysqlPacket(1, mysqlFixtureLogin(flags, []byte("initial-secret"))))
	seq, b, e := mysqlFixtureRead(c)
	if e != nil || seq != 2 || b[0] != 0xfe {
		t.Fatal("AuthSwitch lost")
	}
	c.Write(mysqlPacket(3, []byte("opaque-switch-secret")))
	seq, b, e = mysqlFixtureRead(c)
	if e != nil || seq != 4 || b[0] != 0 {
		t.Fatal("AuthSwitch did not progress")
	}
	c.Close()
	o.wait(t)
	close(events)
	for event := range events {
		if text := fmt.Sprintf("%+v", event); strings.Contains(text, "initial-secret") || strings.Contains(text, "opaque-switch-secret") {
			t.Fatal("AuthSwitch credential exposed")
		}
	}
}

func TestMySQLAsymmetricTLSSequences(t *testing.T) {
	for _, upTLS := range []bool{false, true} {
		t.Run(fmt.Sprint(upTLS), func(t *testing.T) {
			p := makePKI(t)
			o := fixtureOrigin(t, func(raw net.Conn, o *wireOrigin) {
				raw.Write(mysqlPacket(0, mysqlFixtureGreeting(mysqlCapabilities)))
				c := raw
				seq, b, e := mysqlFixtureRead(c)
				if e != nil {
					return
				}
				if upTLS {
					if seq != 1 || len(b) != 32 {
						return
					}
					tc := tls.Server(raw, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{p.pair}})
					if tc.Handshake() != nil {
						return
					}
					c = tc
					seq, b, e = mysqlFixtureRead(c)
					if e != nil || seq != 2 {
						return
					}
				} else if seq != 1 {
					return
				}
				o.record(b)
				c.Write(mysqlPacket(seq+1, mysqlOK(2)))
				io.Copy(io.Discard, c)
			})
			cfg := Config{Protocol: "mysql", Upstream: o.listener.Addr().String(), UpstreamTLS: upTLS}
			if upTLS {
				cfg.UpstreamServerName = "localhost"
				cfg.UpstreamCA = p.ca
			} else {
				cfg.TLSCert = p.cert
				cfg.TLSKey = p.key
			}
			raw, _, _ := startTCPGateway(t, cfg, allowAll())
			mysqlFixtureRead(raw)
			c := raw
			flags := mysqlProtocol41 | mysqlSecure | mysqlPlugin
			seq := byte(1)
			if !upTLS {
				flags |= mysqlSSL
				ssl := make([]byte, 32)
				binary.LittleEndian.PutUint32(ssl, flags)
				raw.Write(mysqlPacket(1, ssl))
				tc := tls.Client(raw, p.client(false))
				if e := tc.Handshake(); e != nil {
					t.Fatal(e)
				}
				c = tc
				seq = 2
			}
			c.Write(mysqlPacket(seq, mysqlFixtureLogin(flags, []byte("opaque"))))
			got, b, e := mysqlFixtureRead(c)
			if e != nil || got != seq+1 || b[0] != 0 {
				t.Fatalf("asymmetric auth sequence: %d %x %v", got, b, e)
			}
			c.Close()
			o.wait(t)
		})
	}
}

func TestMySQLOriginTLSVerificationPrecedesCredentials(t *testing.T) {
	p := makePKI(t)
	o := fixtureOrigin(t, func(raw net.Conn, o *wireOrigin) {
		raw.Write(mysqlPacket(0, mysqlFixtureGreeting(mysqlCapabilities)))
		if _, _, e := mysqlFixtureRead(raw); e != nil {
			return
		}
		c := tls.Server(raw, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{p.pair}})
		if c.Handshake() != nil {
			return
		}
		_, b, e := mysqlFixtureRead(c)
		if e == nil {
			o.record(b)
		}
	})
	c, _, _ := startTCPGateway(t, Config{Protocol: "mysql", Upstream: o.listener.Addr().String(), UpstreamTLS: true, UpstreamServerName: "wrong.invalid", UpstreamCA: p.ca}, allowAll())
	io.ReadAll(c)
	c.Close()
	o.wait(t)
	if len(o.snapshot()) != 0 {
		t.Fatal("authentication reached an unverified TLS peer")
	}
}

func TestMySQLPreparedStateBoundAndClose(t *testing.T) {
	for _, closeFirst := range []bool{false, true} {
		t.Run(fmt.Sprint(closeFirst), func(t *testing.T) {
			o, _ := mysqlFixture(t, false)
			c, _, _ := startTCPGateway(t, Config{Protocol: "mysql", Upstream: o.listener.Addr().String(), MaxStateEntries: 1}, allowAll())
			mysqlTestLogin(t, c, true)
			id, _ := mysqlPrepareTest(t, c, "SELECT 7", true)
			if closeFirst {
				closePacket := []byte{25, byte(id), byte(id >> 8), byte(id >> 16), byte(id >> 24)}
				c.Write(mysqlPacket(0, closePacket))
				id, _ = mysqlPrepareTest(t, c, "SELECT 7", true)
				c.Write(mysqlPacket(0, mysqlExecute(id, false)))
				mysqlTestResult(t, c, true, true)
			} else {
				c.Write(mysqlPacket(0, append([]byte{22}, []byte("SELECT 8")...)))
				_, b, e := mysqlFixtureRead(c)
				if e != nil || b[0] != 0xff {
					t.Fatal("statement bound not enforced")
				}
			}
			c.Close()
			o.wait(t)
			if !closeFirst && bytes.Contains(o.snapshot(), []byte("SELECT 8")) {
				t.Fatal("over-limit prepare reached origin")
			}
		})
	}
}

func TestMySQLPreparedSchemaContextAndUnknownSQLState(t *testing.T) {
	o, _ := mysqlFixture(t, false)
	events := make(chan policy.Event, 20)
	p := evaluateFunc(func(e policy.Event) (policy.Decision, error) {
		events <- e
		return policy.Decision{Verdict: "allow"}, nil
	})
	c, _, _ := startTCPGateway(t, Config{Protocol: "mysql", Upstream: o.listener.Addr().String()}, p)
	mysqlTestLogin(t, c, true)
	c.Write(mysqlPacket(0, append([]byte{2}, []byte("first")...)))
	mysqlTestResult(t, c, true, false)
	id, _ := mysqlPrepareTest(t, c, "SELECT 7", true)
	c.Write(mysqlPacket(0, append([]byte{2}, []byte("second")...)))
	mysqlTestResult(t, c, true, false)
	c.Write(mysqlPacket(0, mysqlExecute(id, false)))
	mysqlTestResult(t, c, true, true)
	c.Write(mysqlPacket(0, append([]byte{3}, []byte("SELECT empty")...)))
	mysqlTestResult(t, c, true, false)
	c.Write(mysqlPacket(0, []byte{14}))
	mysqlTestResult(t, c, true, false)
	c.Close()
	o.wait(t)
	close(events)
	executeSeen, unknownSeen := false, false
	for e := range events {
		if e.Method == "STMT_EXECUTE" {
			executeSeen = true
			if e.Attributes["db.database"] != "first" {
				t.Fatalf("execute lost prepare-time schema: %+v", e.Attributes)
			}
		}
		if e.Method == "PING" {
			unknownSeen = true
			if _, present := e.Attributes["db.database"]; present {
				t.Fatal("schema invented after arbitrary SQL")
			}
		}
	}
	if !executeSeen || !unknownSeen {
		t.Fatal("missing context events")
	}
}
