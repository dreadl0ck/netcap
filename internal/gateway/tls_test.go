package gateway

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type testPKI struct {
	cert, key, ca string
	pair          tls.Certificate
	roots         *x509.CertPool
}

func makePKI(t *testing.T) testPKI {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"localhost"}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cp := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	kp := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: secret})
	root := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	dir := t.TempDir()
	p := testPKI{cert: filepath.Join(dir, "cert.pem"), key: filepath.Join(dir, "key.pem"), ca: filepath.Join(dir, "ca.pem"), roots: x509.NewCertPool()}
	for path, b := range map[string][]byte{p.cert: cp, p.key: kp, p.ca: root} {
		if err := os.WriteFile(path, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	p.pair, err = tls.X509KeyPair(cp, kp)
	if err != nil {
		t.Fatal(err)
	}
	p.roots.AppendCertsFromPEM(root)
	return p
}
func (p testPKI) client(cert bool) *tls.Config {
	c := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: "localhost", RootCAs: p.roots}
	if cert {
		c.Certificates = []tls.Certificate{p.pair}
	}
	return c
}

func TestTLSMutualListenerAndVerifiedOrigin(t *testing.T) {
	p := makePKI(t)
	o := fixtureOrigin(t, func(raw net.Conn, o *wireOrigin) {
		c := tls.Server(raw, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{p.pair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: p.roots})
		if c.Handshake() != nil {
			return
		}
		b, e := readRESP(bufio.NewReader(c), 4096, 0)
		if e != nil {
			return
		}
		o.record(b)
		c.Write([]byte("+PONG\r\n"))
	})
	cfg := Config{Protocol: "redis", Upstream: o.listener.Addr().String(), TLSCert: p.cert, TLSKey: p.key, ClientCA: p.ca, UpstreamTLS: true, UpstreamServerName: "localhost", UpstreamCA: p.ca, UpstreamCert: p.cert, UpstreamKey: p.key}
	raw, _, _ := startTCPGateway(t, cfg, allowAll())
	c := tls.Client(raw, p.client(true))
	if e := c.Handshake(); e != nil {
		t.Fatal(e)
	}
	c.Write(respCommand("PING"))
	wantRESP(t, bufio.NewReader(c), "+PONG\r\n")
	c.Close()
	o.wait(t)
	if len(o.snapshot()) == 0 {
		t.Fatal("mutually verified TLS did not forward command")
	}
}
func TestOriginTLSMismatchNeverSendsApplicationBytes(t *testing.T) {
	for _, bad := range []string{"name", "ca"} {
		t.Run(bad, func(t *testing.T) {
			p := makePKI(t)
			o := fixtureOrigin(t, func(raw net.Conn, o *wireOrigin) {
				c := tls.Server(raw, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{p.pair}})
				if c.Handshake() != nil {
					return
				}
				b := make([]byte, 4096)
				n, _ := c.Read(b)
				o.record(b[:n])
			})
			cfg := Config{Protocol: "redis", Upstream: o.listener.Addr().String(), UpstreamTLS: true, UpstreamServerName: "localhost", UpstreamCA: p.ca}
			if bad == "name" {
				cfg.UpstreamServerName = "wrong.invalid"
			} else {
				cfg.UpstreamCA = makePKI(t).ca
			}
			c, _, _ := startTCPGateway(t, cfg, allowAll())
			c.Write(respCommand("SET", "never", "secret"))
			io.ReadAll(c)
			c.Close()
			o.wait(t)
			if len(o.snapshot()) != 0 {
				t.Fatal("TLS failure leaked application bytes")
			}
		})
	}
}
func TestListenerMTLSRejectsUntrustedClient(t *testing.T) {
	p := makePKI(t)
	o := fixtureOrigin(t, func(c net.Conn, o *wireOrigin) { o.record([]byte("connected")) })
	raw, _, _ := startTCPGateway(t, Config{Protocol: "redis", Upstream: o.listener.Addr().String(), TLSCert: p.cert, TLSKey: p.key, ClientCA: p.ca}, allowAll())
	c := tls.Client(raw, p.client(false))
	c.Handshake()
	c.Write(respCommand("PING"))
	io.ReadAll(c)
	c.Close()
	if len(o.snapshot()) != 0 {
		t.Fatal("client without certificate reached origin")
	}
	o.listener.Close()
	o.wait(t)
}
func TestPostgresExplicitTLSNegotiation(t *testing.T) {
	p := makePKI(t)
	o := pgFixture(t)
	raw, _, _ := startTCPGateway(t, Config{Protocol: "postgres", Upstream: o.listener.Addr().String(), TLSCert: p.cert, TLSKey: p.key}, allowAll())
	raw.Write([]byte{0, 0, 0, 8, 4, 210, 22, 47})
	var h [1]byte
	if _, e := io.ReadFull(raw, h[:]); e != nil || h[0] != 'S' {
		t.Fatal("SSLRequest not accepted explicitly")
	}
	c := tls.Client(raw, p.client(false))
	if err := c.HandshakeContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	pgLogin(t, c)
	c.Write(pgFrame('Q', []byte("SELECT 1\x00")))
	pgReceive(t, c, 'Z')
	c.Close()
	o.wait(t)
}

func TestPostgresVerifiedTLSOriginSSLRequest(t *testing.T) {
	p := makePKI(t)
	o := fixtureOrigin(t, func(raw net.Conn, o *wireOrigin) {
		b, e := readPG(raw, true)
		if e != nil || !bytes.Equal(b, []byte{0, 0, 0, 8, 4, 210, 22, 47}) {
			return
		}
		raw.Write([]byte("S"))
		c := tls.Server(raw, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{p.pair}})
		if c.Handshake() != nil {
			return
		}
		b, e = readPG(c, true)
		if e != nil {
			return
		}
		o.record(b)
		c.Write(append(pgFrame('R', []byte{0, 0, 0, 0}), pgFrame('Z', []byte{'I'})...))
		io.Copy(io.Discard, c)
	})
	c, _, _ := startTCPGateway(t, Config{Protocol: "postgres", Upstream: o.listener.Addr().String(), UpstreamTLS: true, UpstreamServerName: "localhost", UpstreamCA: p.ca}, allowAll())
	pgTrustLogin(t, c)
	c.Close()
	o.wait(t)
	if !bytes.Equal(o.snapshot(), startupPacket()) {
		t.Fatal("Postgres startup did not cross verified TLS")
	}
}
func TestDNSOverTLS(t *testing.T) {
	p := makePKI(t)
	o := fixtureOrigin(t, func(raw net.Conn, o *wireOrigin) {
		c := tls.Server(raw, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{p.pair}})
		if c.Handshake() != nil {
			return
		}
		var h [2]byte
		if _, e := io.ReadFull(c, h[:]); e != nil {
			return
		}
		b := make([]byte, word(h[:]))
		if _, e := io.ReadFull(c, b); e != nil {
			return
		}
		o.record(b)
		r := dnsAnswer(b)
		c.Write(append([]byte{byte(len(r) >> 8), byte(len(r))}, r...))
	})
	raw, _, _ := startTCPGateway(t, Config{Protocol: "dns-tls", Upstream: o.listener.Addr().String(), TLSCert: p.cert, TLSKey: p.key, UpstreamTLS: true, UpstreamServerName: "localhost", UpstreamCA: p.ca}, allowAll())
	c := tls.Client(raw, p.client(false))
	if e := c.Handshake(); e != nil {
		t.Fatal(e)
	}
	q := dnsRequest(t, "example.test.")
	c.Write(append([]byte{byte(len(q) >> 8), byte(len(q))}, q...))
	var h [2]byte
	if _, e := io.ReadFull(c, h[:]); e != nil {
		t.Fatal(e)
	}
	b := make([]byte, word(h[:]))
	if _, e := io.ReadFull(c, b); e != nil {
		t.Fatal(e)
	}
	m, _ := parseDNSQuery(q)
	if e := validateDNSResponse(q, b, m); e != nil {
		t.Fatal(e)
	}
	c.Close()
	o.wait(t)
}

func TestEDNSBoundsAndErrorReplyEnvelope(t *testing.T) {
	query := func(size uint16, ttl uint32, options []byte) []byte {
		b := dnsRequest(t, "example.test.")
		b[11] = 1
		b = append(b, 0, 0, 41, byte(size>>8), byte(size), byte(ttl>>24), byte(ttl>>16), byte(ttl>>8), byte(ttl), byte(len(options)>>8), byte(len(options)))
		return append(b, options...)
	}
	good := query(1232, 0x8000, []byte{0, 12, 0, 4, 0, 0, 0, 0})
	if _, e := parseDNSQuery(good); e != nil {
		t.Fatal(e)
	}
	r := dnsReply(good, 5, false)
	if validateDNSWire(r) != nil || word(r[10:12]) != 0 {
		t.Fatalf("OPT trailing into error response: %x", r)
	}
	for _, b := range [][]byte{query(511, 0, nil), query(4097, 0, nil), query(1232, 1<<16, nil), query(1232, 0, []byte{0, 1, 0, 10})} {
		if _, e := parseDNSQuery(b); e == nil {
			t.Fatalf("bad EDNS accepted %x", b)
		}
	}
}
