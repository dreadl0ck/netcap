//go:build coraza

package waf

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/enforcer"
	"github.com/dreadl0ck/netcap/internal/policy"
	"github.com/dreadl0ck/netcap/internal/responseactions"
)

func TestNativeEffectsAndCorazaKeepDecisionAndDeliveryIndependent(t *testing.T) {
	for _, mode := range []string{"enforce", "monitor"} {
		t.Run(mode, func(t *testing.T) {
			var upstream, deliveries atomic.Int64
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { upstream.Add(1); _, _ = io.WriteString(w, "origin") }))
			defer origin.Close()
			endpoint := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { deliveries.Add(1); http.Error(w, "unavailable", 503) }))
			defer endpoint.Close()
			t.Setenv("NETCAP_WAF_TEST_EFFECT_TOKEN", strings.Repeat("t", 32))
			roots := x509.NewCertPool()
			roots.AddCert(endpoint.Certificate())
			broker, err := responseactions.New(responseactions.Config{TLSConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, Scopes: map[string]responseactions.Scope{"edge": {Endpoint: endpoint.URL, TokenEnv: "NETCAP_WAF_TEST_EFFECT_TOKEN", Network: enforcer.Scope{Hook: "input", Interface: "eth0", DestinationCIDR: "198.51.100.0/24", Protocol: "tcp", Port: 443}}}})
			if err != nil {
				t.Fatal(err)
			}
			defer broker.Close()
			p := effectPolicy(t, mode, `Body contains "script"`)
			c := config(origin.URL)
			c.CorazaCRS = true
			f := firewall(t, c, p)
			if err := f.SetEvaluator(func(_ context.Context, p *policy.Compiled, e policy.Event) (policy.Decision, error) {
				return (&responseactions.Evaluator{Policy: p, Broker: broker, Source: func(event policy.Event, target string) (string, bool) { return event.ClientIP, target == "client" }}).Evaluate(e)
			}); err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest("POST", "http://route.example/", strings.NewReader(`field=<script>alert(1)</script>`))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.Header.Set("User-Agent", "WAF integration test")
			r.Header.Set("Accept", "*/*")
			w := httptest.NewRecorder()
			f.ServeHTTP(w, r)
			if mode == "monitor" {
				if w.Code != 200 || upstream.Load() != 1 || deliveries.Load() != 0 || len(broker.Receipts()) != 0 {
					t.Fatalf("monitor delivered effects or blocked: status=%d origin=%d deliveries=%d receipts=%v", w.Code, upstream.Load(), deliveries.Load(), broker.Receipts())
				}
				if f.stats.wouldDeny.Load() != 2 {
					t.Fatalf("native and CRS monitor decisions missing: %d", f.stats.wouldDeny.Load())
				}
			} else {
				if w.Code != 451 || upstream.Load() != 0 {
					t.Fatalf("CRS/broker replaced winning native denial: %d origin=%d", w.Code, upstream.Load())
				}
				deadline := time.Now().Add(3 * time.Second)
				failed := false
				for time.Now().Before(deadline) {
					for _, r := range broker.Receipts() {
						if r.Status == "failed" {
							failed = true
						}
					}
					if failed {
						break
					}
					time.Sleep(5 * time.Millisecond)
				}
				if !failed || deliveries.Load() == 0 {
					t.Fatalf("independent delivery failure not observed: %v", broker.Receipts())
				}
			}
			if f.buffers.Used() != 0 {
				t.Fatalf("Coraza/HTTP quota leaked: %d", f.buffers.Used())
			}
		})
	}
}

func TestCorazaCannotBeBypassedByAllowingEvaluatorHook(t *testing.T) {
	var requests atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1) }))
	defer origin.Close()
	c := config(origin.URL)
	c.CorazaCRS = true
	f := firewall(t, c, compiled(t, "enforce", "request", ""))
	if err := f.SetEvaluator(func(_ context.Context, p *policy.Compiled, e policy.Event) (policy.Decision, error) {
		return p.Evaluate(e)
	}); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "http://route.example/", strings.NewReader(`field=<script>alert(1)</script>`))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("User-Agent", "WAF integration test")
	r.Header.Set("Accept", "*/*")
	w := httptest.NewRecorder()
	f.ServeHTTP(w, r)
	if w.Code != 403 || requests.Load() != 0 || f.buffers.Used() != 0 {
		t.Fatalf("allow hook bypassed CRS: status=%d origin=%d used=%d", w.Code, requests.Load(), f.buffers.Used())
	}
}

func TestCorazaRequestAndResponseShareAggregateQuota(t *testing.T) {
	for _, response := range []bool{false, true} {
		t.Run(map[bool]string{false: "request", true: "response"}[response], func(t *testing.T) {
			var calls atomic.Int64
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "text/plain")
				_, _ = io.WriteString(w, strings.Repeat("a", 64<<10))
			}))
			defer origin.Close()
			c := config(origin.URL)
			c.CorazaCRS = true
			c.MaxBodyBytes = 64 << 10
			c.MaxResponseBytes = 64 << 10
			c.MaxBufferedBytes = 96 << 10
			body := strings.Repeat("a", 32<<10)
			if response {
				c.InspectResponse = true
				c.MaxBufferedBytes = 160 << 10
				body = ""
			}
			f := firewall(t, c, compiled(t, "enforce", "request", ""))
			r := httptest.NewRequest("POST", "http://route.example/", strings.NewReader(body))
			r.Header.Set("Content-Type", "application/octet-stream")
			r.Header.Set("User-Agent", "WAF integration test")
			r.Header.Set("Accept", "*/*")
			if response {
				r.Method = http.MethodGet
				r.Header.Del("Content-Type")
			}
			w := httptest.NewRecorder()
			f.ServeHTTP(w, r)
			wantCalls := int64(0)
			if response {
				wantCalls = 1
			}
			if w.Code != 503 || calls.Load() != wantCalls || f.buffers.Used() != 0 {
				t.Fatalf("Coraza quota not enforced/released: status=%d calls=%d used=%d", w.Code, calls.Load(), f.buffers.Used())
			}
		})
	}
}
