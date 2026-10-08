package protocoltest

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fixtureIdentity struct{ cert, key, pin string }
type fixturePKI struct {
	ca             string
	server, client fixtureIdentity
}

func testPKI(t *testing.T) fixturePKI {
	t.Helper()
	dir := t.TempDir()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "protocol loopback CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, root, root, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	write := func(name, kind string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: b}), 0600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	pki := fixturePKI{ca: write("ca.pem", "CERTIFICATE", der)}
	issue := func(name string, serial int64, usage x509.ExtKeyUsage) fixtureIdentity {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		cert := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name}, DNSNames: []string{"fixture.test"}, NotBefore: root.NotBefore, NotAfter: root.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
		b, err := x509.CreateCertificate(rand.Reader, cert, root, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(b)
		return fixtureIdentity{write(name+".pem", "CERTIFICATE", b), write(name+".key", "PRIVATE KEY", encoded), hex.EncodeToString(sum[:])}
	}
	pki.server = issue("server", 2, x509.ExtKeyUsageServerAuth)
	pki.client = issue("client", 3, x509.ExtKeyUsageClientAuth)
	return pki
}
func secureFixtureExchange(address string, pki fixturePKI) Exchange {
	e := lineExchange(address, Step{Send: []byte("fixture-request-secret-marker\n"), Receive: true, Expect: []byte("fixture-response-secret-marker\n")})
	e.TLS = true
	e.RootCAFile = pki.ca
	e.ServerName = "fixture.test"
	e.ClientCertificateFile = pki.client.cert
	e.ClientKeyFile = pki.client.key
	e.PeerCertificateSHA256 = pki.server.pin
	return e
}
func secureFixtureServer(address string, pki fixturePKI) Exchange {
	e := lineExchange(address, Step{Receive: true, Expect: []byte("fixture-request-secret-marker\n")}, Step{Send: []byte("fixture-response-secret-marker\n")})
	e.TLS = true
	e.ServerTLS = &ServerTLS{CertificateFile: pki.server.cert, KeyFile: pki.server.key, ClientCAFile: pki.ca, PeerCertificateSHA256: pki.client.pin}
	return e
}
func TestTLSServerExplicitTrustMutualAuthenticationAndPins(t *testing.T) {
	pki := testPKI(t)
	for _, mode := range []string{"valid", "no-client-cert", "bad-client-pin", "bad-server-pin", "wrong-host", "untrusted-client"} {
		t.Run(mode, func(t *testing.T) {
			l := loopback(t)
			server := secureFixtureServer(l.Addr().String(), pki)
			client := secureFixtureExchange(l.Addr().String(), pki)
			switch mode {
			case "no-client-cert":
				client.ClientCertificateFile = ""
				client.ClientKeyFile = ""
			case "bad-client-pin":
				server.ServerTLS.PeerCertificateSHA256 = strings.Repeat("0", 64)
			case "bad-server-pin":
				client.PeerCertificateSHA256 = strings.Repeat("0", 64)
			case "wrong-host":
				client.ServerName = "wrong.invalid"
			case "untrusted-client":
				other := testPKI(t)
				client.ClientCertificateFile = other.client.cert
				client.ClientKeyFile = other.client.key
			}
			done := make(chan Result, 1)
			go func() { r, _ := ServeOne(context.Background(), l, server); done <- r }()
			r, err := Run(context.Background(), client)
			s := <-done
			if mode == "valid" {
				if err != nil || s.Status != "matched" || r.TLSVersion == 0 || s.TLSVersion == 0 || len(s.Observations) != 2 {
					t.Fatalf("TLS emulation %+v %+v %v", s, r, err)
				}
			} else if err == nil || s.Status == "matched" {
				t.Fatalf("negative TLS control accepted %+v %+v", r, s)
			}
		})
	}
}

func TestProxyUpstreamMTLSAndEndToEndPassthrough(t *testing.T) {
	pki := testPKI(t)
	for _, mode := range []string{"application", "bad-pin", "passthrough"} {
		t.Run(mode, func(t *testing.T) {
			upstream := loopback(t)
			serverDone := make(chan Result, 1)
			go func() {
				s := secureFixtureServer(upstream.Addr().String(), pki)
				if mode == "passthrough" {
					// Consume the peer's close_notify before closing TCP; closing with
					// unread ciphertext can produce a real RST, which the proxy reports.
					c, err := upstream.Accept()
					if err != nil {
						serverDone <- Result{Error: err.Error()}
						return
					}
					defer c.Close()
					cfg, err := serverTLSConfig(*s.ServerTLS)
					if err != nil {
						serverDone <- Result{Error: err.Error()}
						return
					}
					secure := tls.Server(c, cfg)
					ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
					defer cancel()
					if err = secure.HandshakeContext(ctx); err != nil {
						serverDone <- Result{Error: err.Error()}
						return
					}
					r, err := runConnection(ctx, secure, s, Result{Status: "error"})
					if err == nil {
						err = secure.CloseWrite()
					}
					if err == nil {
						var b [1]byte
						_, err = secure.Read(b[:])
						if err == io.EOF {
							err = nil
						}
					}
					if err != nil {
						r.Status = "error"
						r.Error = err.Error()
					}
					serverDone <- r
					return
				}
				r, _ := ServeOne(context.Background(), upstream, s)
				serverDone <- r
			}()
			front := loopback(t)
			spec := Proxy{Mode: "application", Address: upstream.Addr().String(), Framing: lineExchange("").Framing, MaxFrames: 128, MaxTotalBytes: 128 << 10, TimeoutMilliseconds: 2000, TLS: &ProxyTLS{CertificateFile: pki.server.cert, KeyFile: pki.server.key, RootCAFile: pki.ca, ServerName: "fixture.test", ClientCertificateFile: pki.client.cert, ClientKeyFile: pki.client.key, PeerCertificateSHA256: pki.server.pin}}
			if mode == "bad-pin" {
				spec.TLS.PeerCertificateSHA256 = strings.Repeat("0", 64)
			}
			if mode == "passthrough" {
				spec.Mode = mode
				spec.TLS = nil
				spec.Framing = Framing{}
			}
			type result struct {
				obs []ProxyObservation
				err error
			}
			done := make(chan result, 1)
			go func() { o, e := ProxyOne(context.Background(), front, spec); done <- result{o, e} }()
			var r Result
			var err error
			if mode == "passthrough" {
				cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: "fixture.test"}
				cfg.RootCAs, err = loadTrust(pki.ca)
				if err != nil {
					t.Fatal(err)
				}
				identity, e := loadIdentity(pki.client.cert, pki.client.key)
				if e != nil {
					t.Fatal(e)
				}
				cfg.Certificates = []tls.Certificate{identity}
				if err = setPeerPin(cfg, pki.server.pin); err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				c, e := (&tls.Dialer{Config: cfg}).DialContext(ctx, "tcp", front.Addr().String())
				if e != nil {
					t.Fatal(e)
				}
				r, err = runConnection(ctx, c, secureFixtureExchange(front.Addr().String(), pki), Result{Status: "error"})
				secure := c.(*tls.Conn)
				if err == nil {
					err = secure.CloseWrite()
				}
				if err == nil {
					var b [1]byte
					_, err = secure.Read(b[:])
					if err == io.EOF {
						err = nil
					}
				}
				_ = c.Close()
			} else {
				r, err = Run(context.Background(), secureFixtureExchange(front.Addr().String(), pki))
			}
			proxy := <-done
			server := <-serverDone
			if mode == "bad-pin" {
				if err == nil || proxy.err == nil || server.Status == "matched" {
					t.Fatal("proxy pin not enforced")
				}
				return
			}
			if err != nil || proxy.err != nil || r.Status != "matched" || server.Status != "matched" || len(proxy.obs) == 0 {
				t.Fatalf("proxy mode %s: observations=%d proxyErr=%v serverStatus=%s serverError=%s clientError=%v", mode, len(proxy.obs), proxy.err, server.Status, server.Error, err)
			}
			for _, o := range proxy.obs {
				if !bytes.Equal(o.Original, o.Transmitted) {
					t.Fatal("unmodified bytes changed")
				}
				if mode == "passthrough" && (o.TLSVersion != 0 || bytes.Contains(o.Original, []byte("secret-marker"))) {
					t.Fatal("passthrough exposed plaintext/claimed TLS termination")
				}
			}
		})
	}
	front := loopback(t)
	if _, err := ProxyOne(context.Background(), front, Proxy{Mode: "passthrough", Mutations: []Mutation{{Drop: true}}}); err == nil {
		t.Fatal("passthrough edits accepted")
	}
}

func udpListener(t *testing.T) net.PacketConn {
	t.Helper()
	p, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}
func TestUDPServerSessionsFreshVariablesAndDatagramBoundaries(t *testing.T) {
	for _, request := range [][]byte{{0, 255, 1}, {9, 0, 8, 7}} {
		p := udpListener(t)
		e := Exchange{Version: 1, Network: "udp", Address: p.LocalAddr().String(), Framing: Framing{MaxBytes: 64}, MaxTotalBytes: 512, TimeoutMilliseconds: 1000, Steps: []Step{{Receive: true, CaptureVariable: "nonce", CaptureLength: len(request)}, {SendVariable: "nonce"}, {Receive: true, ExpectPresent: true}, {SendPresent: true}}}
		done := make(chan Result, 1)
		go func() { r, _ := ServeUDP(context.Background(), p, e); done <- r }()
		client := e
		client.Steps = []Step{{Send: request, Receive: true, Expect: request}, {SendPresent: true, Receive: true, ExpectPresent: true}}
		r, err := Run(context.Background(), client)
		server := <-done
		if err != nil || server.Status != "matched" || r.Status != "matched" || len(server.Observations) != 4 || !bytes.Equal(server.Observations[1].Bytes, request) {
			t.Fatalf("UDP emulation %+v %v", server, err)
		}
	}
}
func TestUDPServerRejectsForeignPeerAndOversizedDatagram(t *testing.T) {
	for _, mode := range []string{"foreign", "oversized", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			p := udpListener(t)
			e := Exchange{Version: 1, Network: "udp", Address: p.LocalAddr().String(), Framing: Framing{MaxBytes: 8}, MaxTotalBytes: 64, TimeoutMilliseconds: 1000, Steps: []Step{{Receive: true, Expect: []byte("hello")}, {Send: []byte("ready")}, {Receive: true}}}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan Result, 1)
			go func() { r, _ := ServeUDP(ctx, p, e); done <- r }()
			c, err := net.Dial("udp", p.LocalAddr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(time.Second))
			_, _ = c.Write([]byte("hello"))
			b := make([]byte, 16)
			if _, err = c.Read(b); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "foreign":
				other, err := net.Dial("udp", p.LocalAddr().String())
				if err != nil {
					t.Fatal(err)
				}
				_, _ = other.Write([]byte("foreign"))
				_ = other.Close()
			case "oversized":
				_, _ = c.Write(bytes.Repeat([]byte{1}, 16))
			case "cancel":
				cancel()
			}
			r := <-done
			if r.Status != "error" || len(r.Observations) != 3 {
				t.Fatalf("UDP failure lost evidence %+v", r)
			}
			if mode == "foreign" && (!strings.Contains(r.Error, "foreign UDP peer") || string(r.Observations[2].Bytes) != "foreign") {
				t.Fatal("mixed UDP peers", r)
			}
			if mode == "oversized" && len(r.Observations[2].Bytes) != 9 {
				t.Fatal("oversize evidence not bounded", r)
			}
		})
	}
}

func TestTLSServerHandshakeAndPassthroughCancellation(t *testing.T) {
	pki := testPKI(t)
	l := loopback(t)
	spec := secureFixtureServer(l.Addr().String(), pki)
	spec.TimeoutMilliseconds = 50
	done := make(chan error, 1)
	go func() { _, err := ServeOne(context.Background(), l, spec); done <- err }()
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	select {
	case err = <-done:
		if err == nil {
			t.Fatal("idle TLS handshake succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("TLS handshake ignored budget")
	}
	front := loopback(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = ProxyOne(ctx, front, Proxy{Mode: "passthrough", MaxFrames: 4, MaxTotalBytes: 128, TimeoutMilliseconds: 1000}); err == nil {
		t.Fatal("passthrough canceled accept succeeded")
	}
}
