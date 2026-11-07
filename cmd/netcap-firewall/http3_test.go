//go:build http3

package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
)

const http3BuildTag = "http3"

func TestShippingHTTP3EnforcesAndStops(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer origin.Close()
	admin := freeAddress(t, "tcp")
	config, _ := runtimeConfig(t, origin.URL, admin)
	cert, key := testCertificate(t)
	raw, err := os.ReadFile(config)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err = json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	cfg["tlsCert"], cfg["tlsKey"] = cert, key
	jsonFile(t, config, cfg)
	udp := freeAddress(t, "udp")
	p := startCLI(t, "", "serve", "--config", config, "--http3-listen", udp)
	waitReady(t, p, httpClient(t), "http://"+admin+"/readyz")
	pool := x509.NewCertPool()
	raw, err = os.ReadFile(cert)
	if err != nil {
		t.Fatal(err)
	}
	pool.AppendCertsFromPEM(raw)
	tr := &http3.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool}}
	defer tr.Close()
	c := &http.Client{Transport: tr, Timeout: 3 * time.Second}
	if got := status(t, c, "https://"+udp+"/bootstrap-blocked"); got != 403 {
		t.Fatalf("HTTP/3 policy status %d", got)
	}
	if got := status(t, c, "https://"+udp+"/ok"); got != 204 {
		t.Fatalf("HTTP/3 upstream status %d", got)
	}
	p.stop(t)
}
