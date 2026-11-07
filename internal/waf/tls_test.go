package waf

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type tlsFixture struct {
	cert, key string
	pair      tls.Certificate
	roots     *x509.CertPool
}

func TestUpstreamClientCertificateRotation(t *testing.T) {
	for _, mode := range []string{"single", "route-files", "route-tls"} {
		t.Run(mode, func(t *testing.T) {
			routed := mode != "single"
			server, client, next := testTLS(t, "origin.local"), testTLS(t, "client.local"), testTLS(t, "next.local")
			trust := client.roots.Clone()
			b, _ := os.ReadFile(next.cert)
			trust.AppendCertsFromPEM(b)
			origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.WriteString(w, r.TLS.PeerCertificates[0].Subject.CommonName)
			}))
			origin.TLS = &tls.Config{Certificates: []tls.Certificate{server.pair}, ClientCAs: trust, ClientAuth: tls.RequireAndVerifyClientCert}
			origin.StartTLS()
			defer origin.Close()
			c := config(origin.URL)
			c.UpstreamCA, c.UpstreamServerName = server.cert, "origin.local"
			c.UpstreamCert, c.UpstreamKey = client.cert, client.key
			if routed {
				r := routeFixture(t, origin.URL, "a", "route.example", "/", 0)
				r.UpstreamCA, r.UpstreamServerName, r.UpstreamCert, r.UpstreamKey = c.UpstreamCA, c.UpstreamServerName, c.UpstreamCert, c.UpstreamKey
				c.Routes = []RouteConfig{r}
			}
			f := firewall(t, c, compiled(t, "enforce", "request", ""))
			reload := f.ReloadTLS
			if mode == "route-files" {
				reload = f.ReloadRoutePolicies
			}
			check := func(want string) {
				t.Helper()
				w := call(f, "")
				if w.Code != 200 || w.Body.String() != want {
					t.Fatalf("status %d identity %q want %q", w.Code, w.Body.String(), want)
				}
			}
			check("client.local")
			cert, _ := os.ReadFile(next.cert)
			key, _ := os.ReadFile(next.key)
			if err := os.WriteFile(client.cert, cert, 0600); err != nil {
				t.Fatal(err)
			}
			if err := reload(); err == nil {
				t.Fatal("incomplete client rotation accepted")
			}
			check("client.local")
			if err := os.WriteFile(client.key, key, 0600); err != nil {
				t.Fatal(err)
			}
			if err := reload(); err != nil {
				t.Fatal(err)
			}
			check("next.local")
		})
	}
}

func testTLS(t *testing.T, name string) tlsFixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cb := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	pb := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb})
	dir := t.TempDir()
	c, k := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err = os.WriteFile(c, cb, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(k, pb, 0600); err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(cb, pb)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(cb)
	return tlsFixture{c, k, pair, roots}
}

func TestUpstreamMTLSAndHostnameVerification(t *testing.T) {
	server, client := testTLS(t, "origin.local"), testTLS(t, "client.local")
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.PeerCertificates) == 0 {
			t.Error("missing client identity")
		}
		w.WriteHeader(200)
	}))
	origin.TLS = &tls.Config{Certificates: []tls.Certificate{server.pair}, ClientCAs: client.roots, ClientAuth: tls.RequireAndVerifyClientCert}
	origin.StartTLS()
	defer origin.Close()
	for _, tc := range []struct {
		name   string
		client bool
		status int
	}{{"origin.local", true, 200}, {"wrong.local", true, 502}, {"origin.local", false, 502}} {
		c := config(origin.URL)
		c.UpstreamCA = server.cert
		c.UpstreamServerName = tc.name
		if tc.client {
			c.UpstreamCert, c.UpstreamKey = client.cert, client.key
		}
		f := firewall(t, c, compiled(t, "enforce", "request", ""))
		if status := call(f, "").Code; status != tc.status {
			t.Fatalf("%s client=%v status=%d", tc.name, tc.client, status)
		}
		r := routeFixture(t, origin.URL, "tenant", "route.example", "/", 0)
		r.UpstreamCA, r.UpstreamServerName, r.UpstreamCert, r.UpstreamKey = c.UpstreamCA, c.UpstreamServerName, c.UpstreamCert, c.UpstreamKey
		c.Routes = []RouteConfig{r}
		routed := firewall(t, c, compiled(t, "enforce", "request", ""))
		if status := call(routed, "").Code; status != tc.status {
			t.Fatalf("routed %s client=%v status=%d", tc.name, tc.client, status)
		}
	}
}

func TestListenerMTLSReloadFailurePreservesIdentityAndPolicy(t *testing.T) {
	listenerReloadBoundary(t, false)
}

func TestRoutedListenerMTLSReloadFailurePreservesIdentityAndPolicy(t *testing.T) {
	listenerReloadBoundary(t, true)
}

func listenerReloadBoundary(t *testing.T, routed bool) {
	server, client, replacement := testTLS(t, "waf.local"), testTLS(t, "client.local"), testTLS(t, "waf.local")
	c := config("http://unused.invalid")
	c.TLSCert, c.TLSKey, c.ClientCA = server.cert, server.key, client.cert
	f, bound, handler := composedFirewall(t, c, compiled(t, "enforce", "request", `Method == "POST"`), routed)
	proxy := httptest.NewUnstartedServer(handler)
	proxy.TLS = f.TLSConfig()
	proxy.StartTLS()
	defer proxy.Close()
	roots := server.roots.Clone()
	b, _ := os.ReadFile(replacement.cert)
	roots.AppendCertsFromPEM(b)
	send := func(withClient bool) (int, []byte, error) {
		cfg := &tls.Config{RootCAs: roots, ServerName: "waf.local"}
		if withClient {
			cfg.Certificates = []tls.Certificate{client.pair}
		}
		tr := &http.Transport{TLSClientConfig: cfg, DisableKeepAlives: true}
		defer tr.CloseIdleConnections()
		req, _ := http.NewRequest("POST", proxy.URL, nil)
		resp, err := (&http.Client{Transport: tr}).Do(req)
		if err != nil {
			return 0, nil, err
		}
		defer resp.Body.Close()
		return resp.StatusCode, resp.TLS.PeerCertificates[0].Raw, nil
	}
	if _, _, err := send(false); err == nil {
		t.Fatal("unauthenticated listener accepted")
	}
	before := bound.Policy()
	certBytes, _ := os.ReadFile(replacement.cert)
	keyBytes, _ := os.ReadFile(replacement.key)
	if err := os.WriteFile(server.cert, certBytes, 0600); err != nil {
		t.Fatal(err)
	}
	if err := f.ReloadTLS(); err == nil {
		t.Fatal("mismatched pair activated")
	}
	if status, der, err := send(true); err != nil || status != 403 || string(der) != string(server.pair.Certificate[0]) {
		t.Fatalf("failed reload changed live state: status=%d err=%v", status, err)
	}
	if err := os.WriteFile(server.key, keyBytes, 0600); err != nil {
		t.Fatal(err)
	}
	if err := f.ReloadTLS(); err != nil {
		t.Fatal(err)
	}
	if status, der, err := send(true); err != nil || status != 403 || string(der) != string(replacement.pair.Certificate[0]) {
		t.Fatalf("reload: status=%d err=%v", status, err)
	}
	if bound.Policy() != before {
		t.Fatal("TLS reload disabled policy")
	}
	untrusted := testTLS(t, "other-client.local")
	previous := client.pair
	client.pair = untrusted.pair
	if _, _, err := send(true); err == nil {
		t.Fatal("untrusted listener client accepted")
	}
	client.pair = previous
	trust, _ := os.ReadFile(untrusted.cert)
	if err := os.WriteFile(client.cert, trust, 0600); err != nil {
		t.Fatal(err)
	}
	if err := f.ReloadTLS(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := send(true); err == nil {
		t.Fatal("old listener client trusted after CA rotation")
	}
	client.pair = untrusted.pair
	if status, _, err := send(true); err != nil || status != 403 {
		t.Fatalf("rotated listener trust: %d %v", status, err)
	}
}

func TestListenerTLSReloadPreservesHTTP2(t *testing.T) {
	server := testTLS(t, "waf.local")
	c := config("http://unused.invalid")
	c.TLSCert, c.TLSKey = server.cert, server.key
	f := firewall(t, c, compiled(t, "enforce", "request", `Method == "GET"`))
	proxy := httptest.NewUnstartedServer(f)
	proxy.EnableHTTP2 = true
	proxy.TLS = f.TLSConfig()
	proxy.StartTLS()
	defer proxy.Close()
	for i := 0; i < 2; i++ {
		tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: server.roots, ServerName: "waf.local"}, ForceAttemptHTTP2: true}
		resp, err := (&http.Client{Transport: tr}).Get(proxy.URL)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		tr.CloseIdleConnections()
		if resp.ProtoMajor != 2 || resp.StatusCode != 403 {
			t.Fatalf("protocol=%s status=%d", resp.Proto, resp.StatusCode)
		}
		if err := f.ReloadTLS(); err != nil {
			t.Fatal(err)
		}
	}
}
