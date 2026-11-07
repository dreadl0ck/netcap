package responseactions

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/enforcer"
	"github.com/dreadl0ck/netcap/internal/policy"
)

var testScope = enforcer.Scope{Hook: "input", Interface: "eth0", DestinationCIDR: "198.51.100.0/24", Protocol: "tcp", Port: 443}

func controller(t *testing.T, dry bool) (*enforcer.Controller, *enforcer.DryRunBackend) {
	t.Helper()
	backend := enforcer.NewDryRunBackend()
	c, err := enforcer.New(enforcer.Config{Token: strings.Repeat("t", 32), Scope: testScope, DryRun: dry, ProtectedCIDRs: []string{"192.0.2.99/32"}}, backend)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c, backend
}

func configFor(t *testing.T, server *httptest.Server) Config {
	t.Helper()
	t.Setenv("NETCAP_TEST_ENFORCER_TOKEN", strings.Repeat("t", 32))
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	return Config{Scopes: map[string]Scope{"edge": {Endpoint: server.URL, TokenEnv: "NETCAP_TEST_ENFORCER_TOKEN", Network: testScope, ProtectedCIDRs: []string{"192.0.2.99/32"}}}, TLSConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
}

func newBroker(t *testing.T, config Config) *Broker {
	t.Helper()
	b, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	return b
}

func intent(source string) policy.Intent {
	now := time.Now().UTC()
	i := policy.Intent{Kind: "block_source", Target: "client", Source: source, Scope: "edge", Revision: strings.Repeat("a", 64), RuleID: "deny", TTL: 10 * time.Second, IssuedAt: now, ExpiresAt: now.Add(10 * time.Second)}
	i.ID = policy.IntentID(i)
	return i
}

func await(t *testing.T, b *Broker, id, status string) Receipt {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, r := range b.Receipts() {
			if r.ID == id && r.Status == status {
				return r
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("missing %s receipt: %+v", status, b.Receipts())
	return Receipt{}
}

func TestRealEnforcerHTTPRecoveryDedupAndDryRun(t *testing.T) {
	for _, dry := range []bool{false, true} {
		t.Run(fmt.Sprint(dry), func(t *testing.T) {
			c, backend := controller(t, dry)
			var posts atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/leases" && r.Method == http.MethodPost && posts.Add(1) == 1 {
					// Apply, then lose the successful reply. GET must recover it.
					capture := httptest.NewRecorder()
					c.Handler().ServeHTTP(capture, r)
					if capture.Code != 201 {
						t.Errorf("enforcer: %d %s", capture.Code, capture.Body.String())
					}
					w.WriteHeader(503)
					return
				}
				c.Handler().ServeHTTP(w, r)
			}))
			defer server.Close()
			b := newBroker(t, configFor(t, server))
			i := intent("192.0.2.5")
			if r := b.Submit(i, i.Source); r.Status != "requested" {
				t.Fatal(r)
			}
			if r := await(t, b, i.ID, "simulated"); r.Reason != "recovered" {
				t.Fatal(r)
			}
			leases, _ := backend.List(context.Background())
			if len(leases) != 1 || !leases[0].ExpiresAt.Equal(i.ExpiresAt) {
				t.Fatalf("leases: %+v", leases)
			}
			expires := leases[0].ExpiresAt
			for n := 0; n < 20; n++ {
				repeat := intent(i.Source)
				if r := b.Submit(repeat, repeat.Source); r.Status != "duplicate" {
					t.Fatal(r)
				}
			}
			leases, _ = backend.List(context.Background())
			if len(leases) != 1 || !leases[0].ExpiresAt.Equal(expires) || posts.Load() != 1 {
				t.Fatal("duplicate renewed lease")
			}
		})
	}
}

func TestTrustScopeProtectedAndFailClosedWrapper(t *testing.T) {
	c, backend := controller(t, false)
	server := httptest.NewTLSServer(c.Handler())
	defer server.Close()
	b := newBroker(t, configFor(t, server))
	for _, tc := range []struct{ source, trusted, scope, reason string }{
		{"192.0.2.1", "192.0.2.2", "edge", "untrusted-source"},
		{"192.0.2.1", "192.0.2.1", "unknown", "unknown-scope"},
		{"192.0.2.99", "192.0.2.99", "edge", "protected-source"},
		{"127.0.0.1", "127.0.0.1", "edge", "untrusted-source"},
	} {
		i := intent(tc.source)
		i.Scope = tc.scope
		i.ID = policy.IntentID(i)
		if r := b.Submit(i, tc.trusted); r.Status != "failed" || r.Reason != tc.reason {
			t.Fatal(r)
		}
	}
	p, err := policy.CompileWithOptions(policy.Bundle{Version: "1", ID: "test", Mode: "enforce", Default: "allow", Rules: []policy.Rule{{ID: "deny", Expression: "true", Action: "deny", Effects: []policy.Effect{{Kind: "block_source", Target: "client", Duration: "10s", Scope: "edge"}}}}}, policy.CompileOptions{AllowEffects: true})
	if err != nil {
		t.Fatal(err)
	}
	wrapper := &Evaluator{Policy: p, Broker: b}
	d, err := wrapper.Evaluate(policy.Event{ClientIP: "192.0.2.1", Headers: map[string][]string{"X-Forwarded-For": {"192.0.2.1"}}})
	if err != nil || d.Verdict != "deny" {
		t.Fatalf("delivery rejection opened decision: %+v %v", d, err)
	}
	await(t, b, d.Effects[0].ID, "failed")
	wrapper.Source = func(e policy.Event, target string) (string, bool) { return e.ClientIP, true }
	wrapper.Replay = true
	d, err = wrapper.Evaluate(policy.Event{ClientIP: "192.0.2.2"})
	if err != nil || len(d.Effects) != 0 {
		t.Fatalf("replay: %+v %v", d, err)
	}
	bundle := p.Bundle()
	bundle.Mode = "monitor"
	wrapper.Policy, _ = policy.CompileWithOptions(bundle, policy.CompileOptions{AllowEffects: true})
	wrapper.Replay = false
	d, err = wrapper.Evaluate(policy.Event{ClientIP: "192.0.2.3"})
	if err != nil || !d.Monitor || len(d.Effects) != 0 {
		t.Fatalf("monitor: %+v %v", d, err)
	}
	leases, _ := backend.List(context.Background())
	if len(leases) != 0 {
		t.Fatalf("untrusted/replay/monitor applied: %+v", leases)
	}
}

func TestQueueOverflowAndBoundedRetention(t *testing.T) {
	entered, release := make(chan struct{}, 1), make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
		w.WriteHeader(503)
	}))
	defer server.Close()
	config := configFor(t, server)
	config.QueueSize = 1
	config.MaxPending = 3
	config.MaxReceipts = 3
	config.Retention = time.Second
	b := newBroker(t, config)
	i := intent("192.0.2.1")
	b.Submit(i, i.Source)
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("worker did not enter")
	}
	i = intent("192.0.2.2")
	b.Submit(i, i.Source)
	i = intent("192.0.2.3")
	if r := b.Submit(i, i.Source); r.Status != "dropped" || r.Reason != "queue-full" {
		t.Fatal(r)
	}
	i = intent("192.0.2.4")
	if r := b.Submit(i, i.Source); r.Status != "dropped" || r.Reason != "dedup-capacity" {
		t.Fatal(r)
	}
	if len(b.Receipts()) > 3 || len(b.seen) > 3 {
		t.Fatal("unbounded retention")
	}
	close(release)
	_ = b.Close()
	if r := b.Submit(i, i.Source); r.Reason != "closed" {
		t.Fatal(r)
	}
	time.Sleep(1050 * time.Millisecond)
	if len(b.Receipts()) != 0 {
		t.Fatal("old receipts retained")
	}
	b.mu.Lock()
	receiptCount := len(b.receipts)
	b.seen["expired"] = time.Now().Add(-time.Second)
	b.mu.Unlock()
	if receiptCount != 0 {
		t.Fatal("expired receipts only hidden, not removed")
	}
	_ = b.Receipts()
	b.mu.Lock()
	_, retained := b.seen["expired"]
	b.mu.Unlock()
	if retained {
		t.Fatal("expired dedup entry retained")
	}
}

func TestTLSVerificationAndEndpointAdmission(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.WriteHeader(503) }))
	defer server.Close()
	config := configFor(t, server)
	config.TLSConfig = nil
	b := newBroker(t, config)
	i := intent("192.0.2.1")
	b.Submit(i, i.Source)
	await(t, b, i.ID, "failed")
	if requests.Load() != 0 {
		t.Fatal("unverified TLS reached HTTP handler")
	}
	for _, endpoint := range []string{"http://localhost", server.URL + "/arbitrary", server.URL + "?token=policy", "https://user:password@localhost"} {
		config = configFor(t, server)
		s := config.Scopes["edge"]
		s.Endpoint = endpoint
		config.Scopes["edge"] = s
		if broker, err := New(config); err == nil {
			_ = broker.Close()
			t.Fatalf("accepted %s", endpoint)
		}
	}
	config = configFor(t, server)
	config.TLSConfig.InsecureSkipVerify = true
	if broker, err := New(config); err == nil {
		_ = broker.Close()
		t.Fatal("accepted insecure TLS")
	}
}

func TestConcurrentSubmissionAndRemoteProtection(t *testing.T) {
	c, backend := controller(t, false)
	server := httptest.NewTLSServer(c.Handler())
	defer server.Close()
	config := configFor(t, server)
	s := config.Scopes["edge"]
	s.ProtectedCIDRs = nil
	config.Scopes["edge"] = s
	b := newBroker(t, config)
	i := intent("192.0.2.99")
	b.Submit(i, i.Source)
	if r := await(t, b, i.ID, "failed"); r.Reason != "enforcer-rejected" {
		t.Fatal(r)
	}
	i = intent("192.0.2.5")
	var wg sync.WaitGroup
	for n := 0; n < 64; n++ {
		wg.Add(1)
		go func() { defer wg.Done(); b.Submit(i, i.Source); _ = b.Receipts() }()
	}
	wg.Wait()
	await(t, b, i.ID, "simulated")
	leases, _ := backend.List(context.Background())
	if len(leases) != 1 {
		t.Fatalf("concurrent lease count: %+v", leases)
	}
}

func TestExpiredQueueIntentNeverPosts(t *testing.T) {
	c, _ := controller(t, true)
	entered, release := make(chan struct{}, 1), make(chan struct{})
	var posts atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/mcp" {
			c.Handler().ServeHTTP(w, r)
			return
		}
		if r.Method == http.MethodPost {
			posts.Add(1)
		}
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
		w.WriteHeader(400)
	}))
	defer server.Close()
	b := newBroker(t, configFor(t, server))
	first := intent("192.0.2.1")
	b.Submit(first, first.Source)
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("worker did not enter")
	}
	i := intent("192.0.2.2")
	i.TTL = time.Second
	i.ExpiresAt = i.IssuedAt.Add(i.TTL)
	i.ID = policy.IntentID(i)
	if r := b.Submit(i, i.Source); r.Status != "requested" {
		t.Fatal(r)
	}
	time.Sleep(1050 * time.Millisecond)
	close(release)
	if r := await(t, b, i.ID, "failed"); r.Reason != "expired-or-closed" {
		t.Fatal(r)
	}
	if posts.Load() != 1 {
		t.Fatal("expired queued intent dispatched")
	}
}
