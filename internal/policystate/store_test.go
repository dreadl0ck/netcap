package policystate

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/firewallstate"
	"github.com/dreadl0ck/netcap/internal/policy"
)

const testToken = "native-policy-state-test-token-32bytes"

var testScope = firewallstate.Scope{Tenant: "one", App: "web"}

func config(t *testing.T) Config {
	t.Helper()
	return Config{StateDir: filepath.Join(t.TempDir(), "state"), Principals: []Principal{{ID: "runtime", Token: testToken, Scope: testScope}, {ID: "other", Token: testToken + "-other", Scope: firewallstate.Scope{Tenant: "two", App: "web"}}}}
}
func store(t *testing.T, cfg Config) *Store {
	t.Helper()
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}
func client(t *testing.T, base, token string) *Client {
	t.Helper()
	c, err := NewClient(ClientConfig{URL: base, Token: token})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}
func descriptor(t *testing.T, id, mode, distinct string, count int) *policy.Compiled {
	t.Helper()
	p, err := policy.Compile(policy.Bundle{Version: "1", ID: id, Mode: "enforce", Default: "allow", Rules: []policy.Rule{{ID: "rate", Action: "deny", Expression: "true", Threshold: &policy.Threshold{Count: count, Window: "1h", Mode: mode, Distinct: distinct, GroupBy: "ClientIP"}}}})
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func request(p *policy.Compiled, e policy.Event) Request {
	raw, _ := json.Marshal(p.Bundle())
	return Request{Revision: p.Revision(), Bundle: raw, Event: &e}
}

func TestSQLiteNativeStateRestartScopeAndBackup(t *testing.T) {
	cfg := config(t)
	s := store(t, cfg)
	server := httptest.NewServer(s.Handler())
	defer server.Close()
	a := client(t, server.URL, testToken)
	b := client(t, server.URL, testToken+"-other")
	p := descriptor(t, "distinct", "sliding", "Network.DstPort", 2)
	e := policy.Event{ClientIP: "192.0.2.5", Body: "request-body-secret", Headers: map[string][]string{"Authorization": {"request-header-secret"}}, Network: policy.NetworkEvent{DstPort: 443}}
	if d, err := a.Evaluate(context.Background(), p, e); err != nil || d.Verdict != "allow" {
		t.Fatal(d, err)
	}
	var snapshot []byte
	var clock int64
	if err := s.disk.DB.QueryRow(`SELECT snapshot FROM policy_states`).Scan(&snapshot); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(snapshot, []byte(e.Body)) || bytes.Contains(snapshot, []byte("request-header-secret")) || bytes.Contains(snapshot, []byte(e.ClientIP)) {
		t.Fatal("snapshot persisted event values")
	}
	if err := s.disk.DB.QueryRow(`SELECT last_ns FROM policy_state_meta`).Scan(&clock); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if err := a.Probe(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	var after int64
	_ = s.disk.DB.QueryRow(`SELECT last_ns FROM policy_state_meta`).Scan(&after)
	if after != clock || !a.Ready() {
		t.Fatal("probe mutated authoritative state/clock")
	}
	e.Network.DstPort = 8443
	if d, err := b.Evaluate(context.Background(), p, e); err != nil || d.Verdict != "allow" {
		t.Fatal("principal scope was client-selectable", d, err)
	}
	backup := filepath.Join(t.TempDir(), "private", "backup.sqlite")
	if err := s.ConsistentBackup(context.Background(), backup); err != nil {
		t.Fatal(err)
	}
	server.Close()
	_ = s.Close()
	s = store(t, cfg)
	server = httptest.NewServer(s.Handler())
	defer server.Close()
	a = client(t, server.URL, testToken)
	if d, err := a.Evaluate(context.Background(), p, e); err != nil || d.Verdict != "deny" {
		t.Fatal("restart forgot first distinct value", d, err)
	}
	if _, err := New(cfg); err == nil {
		t.Fatal("SQLite singleton was not fenced")
	}
	restoredCfg := cfg
	restoredCfg.StateDir = filepath.Join(t.TempDir(), "restored")
	if err := firewallstate.Restore(context.Background(), backup, restoredCfg.StateDir, "policystate"); err != nil {
		t.Fatal(err)
	}
	restored := store(t, restoredCfg)
	if d, err := restored.Evaluate(context.Background(), testScope, request(p, e)); err != nil || d.Verdict != "deny" {
		t.Fatal("consistent backup forgot native state", d, err)
	}
}

func TestNativeSequencesEffectsAndMonitor(t *testing.T) {
	cfg := config(t)
	cfg.AllowEffects = true
	s := store(t, cfg)
	server := httptest.NewServer(s.Handler())
	defer server.Close()
	a := client(t, server.URL, testToken)
	b := policy.Bundle{Version: "1", ID: "sequence", Mode: "enforce", Default: "allow", Rules: []policy.Rule{{ID: "correlation", Action: "deny", Sequence: &policy.Sequence{Name: "dns-tls", Window: "1m", GroupBy: "ClientIP", Steps: []string{`Protocol == "dns"`, `Protocol == "tls"`}}, Effects: []policy.Effect{{Kind: "block_source", Duration: "1m", Target: "client", Scope: "edge"}}}}}
	p, err := policy.CompileWithOptions(b, policy.CompileOptions{AllowEffects: true})
	if err != nil {
		t.Fatal(err)
	}
	if d, err := a.Evaluate(context.Background(), p, policy.Event{Protocol: "dns", ClientIP: "192.0.2.5"}); err != nil || d.Verdict != "allow" {
		t.Fatal(d, err)
	}
	d, err := a.Evaluate(context.Background(), p, policy.Event{Protocol: "tls", ClientIP: "192.0.2.5"})
	if err != nil || d.Verdict != "deny" || len(d.Effects) != 1 || d.Effects[0].ID != policy.IntentID(d.Effects[0]) {
		t.Fatal(d, err)
	}
	if !d.Effects[0].ExpiresAt.After(time.Now()) {
		t.Fatal("server used caller/unbounded clock")
	}
	if p.StateStats().Groups != 0 {
		t.Fatal("remote client advanced its local descriptor")
	}
	b.Mode = "monitor"
	p, err = policy.CompileWithOptions(b, policy.CompileOptions{AllowEffects: true})
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.Evaluate(context.Background(), p, policy.Event{Protocol: "dns", ClientIP: "192.0.2.5"})
	if err != nil {
		t.Fatal(err)
	}
	d, err = a.Evaluate(context.Background(), p, policy.Event{Protocol: "tls", ClientIP: "192.0.2.5"})
	if err != nil || d.Verdict != "would-deny" || len(d.Effects) != 0 {
		t.Fatal("monitor stopped updating or emitted effects", d, err)
	}
	sim, err := p.Simulate([]policy.Event{{Protocol: "dns", ClientIP: "192.0.2.5"}, {Protocol: "tls", ClientIP: "192.0.2.5"}})
	if err != nil || sim[1].Verdict != "would-deny" || len(sim[1].Effects) != 0 {
		t.Fatal(sim, err)
	}
	denied := store(t, config(t))
	if _, err := denied.Evaluate(context.Background(), testScope, request(p, policy.Event{})); err == nil {
		t.Fatal("default effects admission bypassed")
	}
}

func TestBoundsBootstrapClockAndCorruption(t *testing.T) {
	cfg := config(t)
	cfg.MaxRevisions = 1
	s := store(t, cfg)
	p := descriptor(t, "first", "fixed", "", 2)
	e := policy.Event{ClientIP: "one"}
	now := time.Unix(100, 0)
	s.now = func() time.Time { return now }
	if _, err := s.Evaluate(context.Background(), testScope, request(p, e)); err != nil {
		t.Fatal(err)
	}
	other := descriptor(t, "other", "fixed", "", 2)
	if _, err := s.Evaluate(context.Background(), testScope, request(other, e)); err == nil {
		t.Fatal("unbounded revision retention")
	}
	now = now.Add(-time.Hour)
	if d, err := s.Evaluate(context.Background(), testScope, request(p, e)); err != nil || d.Verdict != "deny" {
		t.Fatal("wall-clock reversal reused a window", d, err)
	}
	_ = s.Close()
	changed := cfg
	changed.AllowEffects = true
	if wrong, err := New(changed); err == nil {
		_ = wrong.Close()
		t.Fatal("bootstrap feature admission changed silently")
	}
	s = store(t, cfg)
	if _, err := s.disk.DB.Exec(`UPDATE policy_states SET snapshot=?`, []byte("invalid")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Evaluate(context.Background(), testScope, request(p, e)); err == nil {
		t.Fatal("corrupted snapshot evaluated")
	}
	_ = s.Close()
	if bad, err := New(cfg); err == nil {
		_ = bad.Close()
		t.Fatal("restart accepted corrupt native state")
	}
	smallCfg := config(t)
	smallCfg.MaxStateBytes = 1024
	small := store(t, smallCfg)
	if _, err := small.Evaluate(context.Background(), testScope, request(descriptor(t, "large", "sliding", "", 10000), e)); err == nil {
		t.Fatal("aggregate state byte budget ignored")
	}
	var count int
	_ = small.disk.DB.QueryRow(`SELECT count(*) FROM policy_states`).Scan(&count)
	if count != 0 {
		t.Fatal("failed capacity transition persisted")
	}
}

func TestStrictHTTPAndPinnedRevision(t *testing.T) {
	s := store(t, config(t))
	h := s.Handler()
	p := descriptor(t, "strict", "fixed", "", 2)
	valid, _ := json.Marshal(request(p, policy.Event{}))
	if _, err := s.Evaluate(context.Background(), testScope, request(p, policy.Event{})); err != nil {
		t.Fatal(err)
	}
	poisoned := request(p, policy.Event{})
	poisoned.Bundle = append(append([]byte(nil), poisoned.Bundle[:len(poisoned.Bundle)-1]...), []byte(`,"shell":"forbidden"}`)...)
	if _, err := s.Evaluate(context.Background(), testScope, poisoned); err == nil {
		t.Fatal("cached revision bypassed artifact schema validation")
	}
	for _, body := range []string{`{"revision":"x","revision":"y","event":{}}`, `{"revision":"x","event":{},"scope":{"tenant":"two","app":"web"}}`, `{"revision":"x","Event":{}}`, `{"revision":"x","event":{"ClientIP":"secret"}}`, string(valid) + ` {}`, `null`} {
		r := httptest.NewRequest(http.MethodPost, EvaluatePath, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+testToken)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 400 {
			t.Fatalf("strict schema accepted %d %s", w.Code, body)
		}
	}
	r := httptest.NewRequest(http.MethodGet, HealthPath, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal("health bypassed principal authorization")
	}
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		firewallstate.WriteJSON(w, 200, policy.Decision{Verdict: "allow", Revision: strings.Repeat("b", 64)})
	}))
	defer fake.Close()
	if d, err := client(t, fake.URL, testToken).Evaluate(context.Background(), p, policy.Event{}); err == nil || d.Verdict != "" {
		t.Fatal("client accepted another revision", d, err)
	}
	if _, err := NewClient(ClientConfig{URL: "http://example.com", Token: testToken}); err == nil {
		t.Fatal("non-loopback cleartext accepted")
	}
	if _, err := NewClient(ClientConfig{URL: "https://example.com", Token: testToken, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}); err == nil {
		t.Fatal("insecure TLS transport accepted")
	}
}

func TestAmbiguousResponseIsNotRetriedAndDatabaseFailureIsClosed(t *testing.T) {
	s := store(t, config(t))
	h := s.Handler()
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == EvaluatePath && calls.Add(1) == 1 {
			capture := httptest.NewRecorder()
			h.ServeHTTP(capture, r)
			if capture.Code != 200 {
				t.Errorf("commit status %d", capture.Code)
			}
			connection, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = connection.Close()
			}
			return
		}
		h.ServeHTTP(w, r)
	}))
	defer server.Close()
	c := client(t, server.URL, testToken)
	p := descriptor(t, "ambiguous", "fixed", "", 2)
	if d, err := c.Evaluate(context.Background(), p, policy.Event{}); err == nil || d.Verdict != "" || calls.Load() != 1 {
		t.Fatal("ambiguous operation retried or allowed", d, err, calls.Load())
	}
	if d, err := c.Evaluate(context.Background(), p, policy.Event{}); err != nil || d.Verdict != "deny" {
		t.Fatal("committed transition was forgotten", d, err)
	}
	if err := s.disk.DB.Close(); err != nil {
		t.Fatal(err)
	}
	if d, err := c.Evaluate(context.Background(), p, policy.Event{}); err == nil || d.Verdict != "" || c.Ready() {
		t.Fatal("database failure fell back to local allow", d, err)
	}
	if c.Probe(context.Background()) == nil {
		t.Fatal("closed database remained ready")
	}
}

func TestConcurrentNativeClients(t *testing.T) {
	s := store(t, config(t))
	server := httptest.NewServer(s.Handler())
	defer server.Close()
	c := client(t, server.URL, testToken)
	p := descriptor(t, "concurrent", "sliding", "", 100)
	var wg sync.WaitGroup
	var denied atomic.Int32
	// Keep HTTP admissions below the service's bounded four-request queue.
	for n := 0; n < 4; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 25; i++ {
				d, err := c.Evaluate(context.Background(), p, policy.Event{})
				if err != nil {
					t.Error(err)
					return
				}
				if d.Verdict == "deny" {
					denied.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	if denied.Load() != 1 {
		t.Fatal("lost/double-counted authoritative transitions", denied.Load())
	}
	if p.StateStats().Groups != 0 {
		t.Fatal("descriptor became replica-local state")
	}
}

func TestSharedMaxGroupsDoesNotEvictLiveState(t *testing.T) {
	s := store(t, config(t))
	p := descriptor(t, "full", "fixed", "", 2)
	now := time.Unix(100, 0)
	s.now = func() time.Time { return now }
	if _, err := s.Evaluate(context.Background(), testScope, request(p, policy.Event{ClientIP: "0"})); err != nil {
		t.Fatal(err)
	}
	seed := p.Fork()
	for n := 0; n < policy.MaxGroups; n++ {
		if _, err := seed.EvaluateAt(context.Background(), policy.Event{ClientIP: strconv.Itoa(n)}, now); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := seed.ExportState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.disk.DB.Exec(`UPDATE policy_states SET snapshot=?,accounted=?,watermark=?,expires=?`, raw, seed.StateStats().AccountedBytes+seed.StateProgramBytes(), now.UnixNano(), seed.StateDeadline().UnixNano()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Evaluate(context.Background(), testScope, request(p, policy.Event{ClientIP: "overflow"})); err == nil {
		t.Fatal("shared max-groups exhaustion silently evicted live state")
	}
	var after []byte
	if err := s.disk.DB.QueryRow(`SELECT snapshot FROM policy_states`).Scan(&after); err != nil || !bytes.Equal(raw, after) {
		t.Fatal("capacity error persisted partial state", err)
	}
	now = now.Add(time.Hour)
	if d, err := s.Evaluate(context.Background(), testScope, request(p, policy.Event{ClientIP: "overflow"})); err != nil || d.Verdict != "allow" {
		t.Fatal("expired groups were not reclaimed", d, err)
	}
}

func TestProbeUsesVerifiedTLSAndOrderedOutcomes(t *testing.T) {
	s := store(t, config(t))
	secure := httptest.NewTLSServer(s.Handler())
	defer secure.Close()
	untrusted := client(t, secure.URL, testToken)
	if untrusted.Probe(context.Background()) == nil || untrusted.Ready() {
		t.Fatal("unverified TLS probe succeeded")
	}
	roots := x509.NewCertPool()
	roots.AddCert(secure.Certificate())
	trusted, err := NewClient(ClientConfig{URL: secure.URL, Token: testToken, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}})
	if err != nil {
		t.Fatal(err)
	}
	defer trusted.Close()
	if err := trusted.Probe(context.Background()); err != nil {
		t.Fatal(err)
	}
	p := descriptor(t, "tls", "fixed", "", 2)
	if d, err := trusted.Evaluate(context.Background(), p, policy.Event{}); err != nil || d.Verdict != "allow" {
		t.Fatal(d, err)
	}
	started, release := make(chan struct{}), make(chan struct{})
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == HealthPath {
			close(started)
			<-release
			firewallstate.WriteJSON(w, 200, health{1, true})
			return
		}
		w.WriteHeader(503)
	}))
	defer remote.Close()
	c := client(t, remote.URL, testToken)
	done := make(chan error, 1)
	go func() { done <- c.Probe(context.Background()) }()
	<-started
	if _, err := c.Evaluate(context.Background(), p, policy.Event{}); err == nil {
		t.Fatal("failed evaluation accepted")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if c.Ready() {
		t.Fatal("stale health success overwrote a newer evaluation failure")
	}
}
