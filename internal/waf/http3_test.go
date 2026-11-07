//go:build http3

package waf

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/firewalltransport"
	"github.com/quic-go/quic-go/http3"
)

func TestHTTP3RealTerminationAndLateBodyDenial(t *testing.T) {
	var calls atomic.Int64
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		if r.URL.Path == "/response" {
			_, _ = io.WriteString(w, strings.Repeat("a", (1<<20)+100)+"secret")
			return
		}
		_, _ = io.WriteString(w, "allowed")
	}))
	defer origin.Close()
	c := config(origin.URL)
	c.MaxBodyBytes = 2 << 20
	c.MaxResponseBytes = 2 << 20
	c.InspectResponse = true
	f := firewall(t, c, compiled(t, "enforce", "request", `Body contains "forbidden"`))
	handler, err := f.MessageHandler(false, true)
	if err != nil {
		t.Fatal(err)
	}
	// Reuse the test origin's CA-aware transport for the reverse-proxy hop.
	f.proxy.Transport = origin.Client().Transport
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- firewalltransport.ServeHTTP3(ctx, udp, firewalltransport.HTTP3Config{TLS: origin.TLS, MaxConnections: 4, MaxStreams: 8, IdleTimeout: time.Second, ShutdownTimeout: time.Second}, handler)
	}()
	t.Cleanup(func() {
		defer udp.Close()
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("HTTP/3 server leaked")
		}
	})
	roots := x509.NewCertPool()
	roots.AddCert(origin.Certificate())
	transport := &http3.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}}
	defer transport.Close()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	base := "https://" + udp.LocalAddr().String()
	for _, tc := range []struct {
		body   string
		status int
	}{{"safe", 200}, {strings.Repeat("a", (1<<20)+100) + "forbidden", 403}} {
		resp, err := client.Post(base+"/upload", "application/octet-stream", strings.NewReader(tc.body))
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil || resp.ProtoMajor != 3 || resp.StatusCode != tc.status {
			t.Fatalf("real HTTP/3: proto=%s status=%d body=%q err=%v", resp.Proto, resp.StatusCode, body, err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("late denied upload reached origin: %d", calls.Load())
	}
	var streams sync.WaitGroup
	for i := 0; i < 8; i++ {
		streams.Add(1)
		go func(i int) {
			defer streams.Done()
			body := "safe"
			want := 200
			if i%2 == 0 {
				body = "forbidden"
				want = 403
			}
			resp, err := client.Post(base+"/parallel", "application/octet-stream", strings.NewReader(body))
			if err != nil {
				t.Error(err)
				return
			}
			defer resp.Body.Close()
			_, _ = io.Copy(io.Discard, resp.Body)
			if resp.StatusCode != want {
				t.Errorf("isolated HTTP/3 stream: status=%d want=%d", resp.StatusCode, want)
			}
		}(i)
	}
	streams.Wait()
	if calls.Load() != 5 {
		t.Fatalf("HTTP/3 denied streams crossed boundary: calls=%d", calls.Load())
	}
	unsupported, err := client.Post(base+"/service/method", "application/grpc", strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, unsupported.Body)
	_ = unsupported.Body.Close()
	if unsupported.ProtoMajor != 3 || unsupported.StatusCode != 400 || calls.Load() != 5 {
		t.Fatalf("gRPC-over-HTTP/3 was falsely accepted: proto=%s status=%d origin=%d", unsupported.Proto, unsupported.StatusCode, calls.Load())
	}
	f.SetPolicy(compiled(t, "enforce", "response", `Body contains "secret"`))
	resp, err := client.Get(base + "/response")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil || resp.StatusCode != 403 || strings.Contains(string(body), "secret") {
		t.Fatalf("late response deny leaked: status=%d bytes=%d err=%v", resp.StatusCode, len(body), err)
	}
}
