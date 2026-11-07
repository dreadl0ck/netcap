package firewallstate

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/policy"
)

var testScope = Scope{Tenant: "tenant-a", App: "web"}

const testToken = "principal-a-secret-token"

func stateConfig(t *testing.T) Config {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "state")
	return Config{StateDir: dir, Principals: []Principal{{ID: "a", Token: testToken, Scope: testScope}, {ID: "b", Token: "principal-b-secret-token", Scope: Scope{Tenant: "tenant-b", App: "web"}}}}
}
func TestAtomicClientsScopesAndRevisionIsolation(t *testing.T) {
	cfg := stateConfig(t)
	cfg.Principals = append(cfg.Principals, Principal{ID: "same-scope", Token: "another-principal-same-scope", Scope: testScope})
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	key := Key{Revision: Digest("revision1"), Group: Digest("client")}
	window := Window{Mode: "fixed", Duration: time.Hour}
	const n = 80
	counts := make(chan int64, n)
	errs := make(chan error, n)
	var wg sync.WaitGroup
	for range 8 {
		c, e := NewClient(ClientConfig{URL: srv.URL, Token: testToken})
		if e != nil {
			t.Fatal(e)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 10 {
				v, e := c.Count(context.Background(), key, window, time.Time{})
				if e != nil {
					errs <- e
				} else {
					counts <- v.Count
				}
			}
		}()
	}
	wg.Wait()
	close(counts)
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
	seen := map[int64]bool{}
	for n := range counts {
		if seen[n] {
			t.Fatalf("duplicate count %d", n)
		}
		seen[n] = true
	}
	if len(seen) != n || !seen[n] {
		t.Fatalf("counts %v", seen)
	}
	shared, _ := NewClient(ClientConfig{URL: srv.URL, Token: "another-principal-same-scope"})
	next, e := shared.Count(context.Background(), key, window, time.Time{})
	if e != nil || next.Count != n+1 {
		t.Fatalf("same-scope principals did not share %+v %v", next, e)
	}
	for _, tc := range []struct {
		token string
		key   Key
	}{{"principal-b-secret-token", key}, {testToken, Key{Revision: Digest("revision2"), Group: key.Group}}} {
		c, _ := NewClient(ClientConfig{URL: srv.URL, Token: tc.token})
		v, e := c.Count(context.Background(), tc.key, window, time.Time{})
		if e != nil || v.Count != 1 {
			t.Fatalf("isolation: %+v %v", v, e)
		}
	}
}

func TestRemoteTimeoutRedirectAndWindowMode(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(200 * time.Millisecond):
		}
	}))
	defer slow.Close()
	c, err := NewClient(ClientConfig{URL: slow.URL, Token: testToken, Timeout: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err = c.Count(context.Background(), Key{Digest("r"), Digest("g")}, Window{Mode: "fixed", Duration: time.Second}, time.Time{})
	if err == nil || time.Since(start) > time.Second {
		t.Fatalf("timeout not bounded %v %v", time.Since(start), err)
	}
	var received atomic.Bool
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { received.Store(true) }))
	defer other.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, other.URL, 307) }))
	defer redirect.Close()
	c, _ = NewClient(ClientConfig{URL: redirect.URL, Token: testToken})
	_, err = c.Count(context.Background(), Key{Digest("r"), Digest("g")}, Window{Mode: "fixed", Duration: time.Second}, time.Time{})
	if err == nil || received.Load() {
		t.Fatal("redirect followed with bearer")
	}
	s, err := New(stateConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err = s.Bind(testScope).Count(context.Background(), Key{Digest("r"), Digest("g")}, Window{Mode: "sliding", Duration: time.Second}, time.Now()); err == nil {
		t.Fatal("unsupported sliding window accepted")
	}
}
func TestCapacityTTLAndRestart(t *testing.T) {
	cfg := stateConfig(t)
	cfg.MaxKeys = 1
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	store := s.Bind(testScope)
	now := time.Now()
	key := Key{Digest("r"), Digest("g")}
	w := Window{Mode: "fixed", Duration: time.Second}
	if _, err = store.Count(context.Background(), key, w, now); err != nil {
		t.Fatal(err)
	}
	if _, err = store.Count(context.Background(), key, Window{Mode: "fixed", Duration: 2 * time.Second}, now); err == nil {
		t.Fatal("window mutation accepted")
	}
	other := Key{key.Revision, Digest("other")}
	if _, err = store.Count(context.Background(), other, w, now); err == nil {
		t.Fatal("capacity silently evicted live state")
	}
	if _, err = New(cfg); err == nil {
		t.Fatal("second writer accepted")
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	store = s.Bind(testScope)
	v, err := store.Count(context.Background(), key, w, now)
	if err != nil || v.Count != 2 {
		t.Fatalf("restart lost count: %+v %v", v, err)
	}
	v, err = store.Count(context.Background(), other, w, now.Add(time.Second))
	if err != nil || v.Count != 1 {
		t.Fatalf("expired state not reclaimed: %+v %v", v, err)
	}
}
func TestGuardFailsClosedOnPartition(t *testing.T) {
	s, err := New(stateConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	srv := httptest.NewServer(s.Handler())
	g, err := NewGuard(GuardConfig{URL: srv.URL, Token: testToken, Window: time.Hour, Limit: 1, ID: "global-limit", GroupBy: "ClientIP"})
	if err != nil {
		t.Fatal(err)
	}
	c, err := policy.Compile(policy.Bundle{Version: "1", ID: "allow", Mode: "enforce", Default: "allow"})
	if err != nil {
		t.Fatal(err)
	}
	if ready, _ := g.Ready(); ready {
		t.Fatal("ready before contact")
	}
	for i, want := range []string{"allow", "deny"} {
		d, e := g.Evaluate(context.Background(), c, policy.Event{ClientIP: "127.0.0.1"})
		if e != nil || d.Verdict != want || i == 1 && d.Status != 429 {
			t.Fatalf("decision %+v %v", d, e)
		}
	}
	srv.Close()
	d, err := g.Evaluate(context.Background(), c, policy.Event{ClientIP: "127.0.0.1"})
	if err == nil || d.Verdict != "deny" || d.Status != 503 {
		t.Fatalf("partition allowed %+v %v", d, err)
	}
	if ready, _ := g.Ready(); ready {
		t.Fatal("ready during partition")
	}
}
func TestAuthAndTLS(t *testing.T) {
	for _, url := range []string{"http://example.com", "http://localhost:1234", "https://user:pass@example.com", "https://example.com/?x=1"} {
		if _, err := NewClient(ClientConfig{URL: url, Token: testToken}); err == nil {
			t.Fatalf("unsafe URL accepted %s", url)
		}
	}
	s, err := New(stateConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, tc := range []struct {
		token, body string
		status      int
	}{{"foreign-token", `{}`, 401}, {testToken, `{"scope":{"tenant":"other","app":"web"}}`, 400}, {testToken, `{"key":{},"key":{}}`, 400}} {
		req := httptest.NewRequest("POST", "/api/v1/state/count", strings.NewReader(tc.body))
		req.Header.Set("Authorization", "Bearer "+tc.token)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, req)
		if w.Code != tc.status {
			t.Fatalf("status %d: %s", w.Code, w.Body.String())
		}
	}
}
func TestBackupRestore(t *testing.T) {
	cfg := stateConfig(t)
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	key := Key{Digest("revision"), Digest("group")}
	now := time.Now()
	w := Window{Mode: "fixed", Duration: time.Hour}
	if _, err = s.Bind(testScope).Count(context.Background(), key, w, now); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(t.TempDir(), "private", "backup.sqlite")
	if err = s.Backup(context.Background(), backup); err != nil {
		t.Fatal(err)
	}
	if err = s.Backup(context.Background(), backup); err == nil {
		t.Fatal("backup overwritten")
	}
	dir := filepath.Join(t.TempDir(), "restored")
	if err = Restore(context.Background(), backup, dir, "sharedstate"); err != nil {
		t.Fatal(err)
	}
	cfg.StateDir = dir
	restored, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	v, err := restored.Bind(testScope).Count(context.Background(), key, w, now)
	if err != nil || v.Count != 2 {
		t.Fatalf("restore %+v %v", v, err)
	}
}

type brokenStore struct{}

func (brokenStore) Count(context.Context, Key, Window, time.Time) (CountResult, error) {
	return CountResult{}, errors.New("partition")
}

var _ Store = brokenStore{}
