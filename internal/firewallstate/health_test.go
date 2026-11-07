package firewallstate

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/policy"
)

func TestHealthProbeDoesNotCountPruneOrAdvanceClock(t *testing.T) {
	s, err := New(stateConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	key := Key{Digest("seed"), Digest("expired")}
	if _, err = s.Bind(testScope).Count(context.Background(), key, Window{Mode: "fixed", Duration: time.Millisecond}, time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	type state struct{ rows, count, expires, clock int64 }
	snapshot := func() state {
		t.Helper()
		var v state
		err := s.disk.DB.QueryRow(`SELECT count(*),sum(count),sum(expires),(SELECT last_ns FROM counter_clock WHERE id=1) FROM counters`).Scan(&v.rows, &v.count, &v.expires, &v.clock)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	before := snapshot()
	client, err := NewClient(ClientConfig{URL: srv.URL, Token: testToken})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	remote, err := NewGuardWithStore(GuardConfig{ID: "health", Window: time.Hour, Limit: 1}, client)
	if err != nil {
		t.Fatal(err)
	}
	local := guardForUnit(t, s, "local", "request")
	if ready, _ := remote.Ready(); ready {
		t.Fatal("ready before probe")
	}
	for range 3 {
		if err = remote.Probe(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err = local.Probe(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if ready, err := remote.Ready(); !ready || err != nil {
		t.Fatalf("probe not reflected in readiness: %v %v", ready, err)
	}
	if after := snapshot(); after != before {
		t.Fatalf("probe mutated state: before=%+v after=%+v", before, after)
	}
	c := guardPolicy(t, "quota")
	guardDecision(t, remote, c, policy.Event{}, 0)
	guardDecision(t, remote, c, policy.Event{}, 429)
}

func TestHealthAuthenticationOriginAndMethods(t *testing.T) {
	s, err := New(stateConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, tc := range []struct {
		name, method, token, origin, query string
		want                               int
	}{
		{"healthy", "GET", testToken, "", "", 200},
		{"unauthorized", "GET", "wrong-principal-token", "", "", 401},
		{"origin", "GET", testToken, "https://example.com", "", 403},
		{"method", "POST", testToken, "", "", 405},
		{"scope-claim", "GET", testToken, "", "?tenant=foreign", 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, "/api/v1/state/health"+tc.query, nil)
			r.Header.Set("Authorization", "Bearer "+tc.token)
			if tc.origin != "" {
				r.Header.Set("Origin", tc.origin)
			}
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
			if tc.want == 200 && strings.TrimSpace(w.Body.String()) != `{"ready":true}` {
				t.Fatalf("unexpected health payload: %s", w.Body.String())
			}
		})
	}
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	client, _ := NewClient(ClientConfig{URL: srv.URL, Token: "wrong-principal-token"})
	defer client.Close()
	if err = client.Probe(context.Background()); err == nil {
		t.Fatal("client probe accepted wrong token")
	}
}

func TestHealthChecksLiveDatabaseAndHonorsDeadline(t *testing.T) {
	s, err := New(stateConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	client, _ := NewClient(ClientConfig{URL: srv.URL, Token: testToken})
	defer client.Close()
	g, err := NewGuardWithStore(GuardConfig{ID: "health", Window: time.Hour, Limit: 1}, client)
	if err != nil {
		t.Fatal(err)
	}
	if err = g.Probe(context.Background()); err != nil {
		t.Fatal(err)
	}
	conn, err := s.disk.DB.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	start := time.Now()
	err = g.Probe(ctx)
	cancel()
	_ = conn.Close()
	if err == nil || time.Since(start) > time.Second {
		t.Fatalf("blocked SQL probe not bounded: %v", err)
	}
	if ready, _ := g.Ready(); ready {
		t.Fatal("blocked SQL returned cached healthy status")
	}
	if err = g.Probe(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err = s.disk.DB.Exec(`UPDATE metadata SET version=2`); err != nil {
		t.Fatal(err)
	}
	if err = g.Probe(context.Background()); err == nil {
		t.Fatal("invalid live metadata reported ready")
	}
	if err = s.disk.DB.Close(); err != nil {
		t.Fatal(err)
	}
	if err = g.Probe(context.Background()); err == nil {
		t.Fatal("closed SQL database reported ready")
	}
	if ready, _ := g.Ready(); ready {
		t.Fatal("closed SQL left guard ready")
	}
}

func TestHealthProbeConcurrencyCapacity(t *testing.T) {
	s, err := New(stateConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for range cap(s.slots) {
		s.slots <- struct{}{}
	}
	defer func() {
		for range cap(s.slots) {
			<-s.slots
		}
	}()
	r := httptest.NewRequest("GET", "/api/v1/state/health", nil)
	r.Header.Set("Authorization", "Bearer "+testToken)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 503 {
		t.Fatalf("overloaded health returned %d", w.Code)
	}
	if err = s.Bind(testScope).(healthStore).Probe(context.Background()); err == nil {
		t.Fatal("bound probe ignored capacity")
	}
}

func TestClientHealthResponseValidation(t *testing.T) {
	for _, body := range []string{`{"ready":false}`, `{}`, `{"ready":true,"extra":1}`, `{"ready":true,"ready":false}`, `{"ready":"true"}`, strings.Repeat(" ", 2049) + `{"ready":true}`} {
		t.Run(body[:min(len(body), 30)], func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" || r.URL.Path != "/api/v1/state/health" || Bearer(r) != testToken || r.Header.Get("Origin") != "" {
					t.Error("invalid client health request")
				}
				_, _ = w.Write([]byte(body))
			}))
			defer srv.Close()
			c, _ := NewClient(ClientConfig{URL: srv.URL, Token: testToken})
			defer c.Close()
			if err := c.Probe(context.Background()); err == nil {
				t.Fatal("invalid health response accepted")
			}
		})
	}
}

type countOnlyStore struct{ calls atomic.Int32 }

func (s *countOnlyStore) Count(context.Context, Key, Window, time.Time) (CountResult, error) {
	s.calls.Add(1)
	return CountResult{Count: 1, Expires: time.Now().Add(time.Hour)}, nil
}
func TestGuardProbeRequiresHealthSupport(t *testing.T) {
	store := &countOnlyStore{}
	g, err := NewGuardWithStore(GuardConfig{ID: "health", Window: time.Hour, Limit: 1}, store)
	if err != nil {
		t.Fatal(err)
	}
	if err = g.Probe(context.Background()); err == nil || !strings.Contains(err.Error(), "store cannot probe") {
		t.Fatalf("unsupported store: %v", err)
	}
	if store.calls.Load() != 0 {
		t.Fatal("probe fell back to consuming a count")
	}
	if ready, _ := g.Ready(); ready {
		t.Fatal("unsupported store fabricated readiness")
	}
}

type orderedHealthStore struct {
	blockProbe bool
	entered    chan struct{}
	release    chan struct{}
	once       sync.Once
}

func (s *orderedHealthStore) wait(ctx context.Context) error {
	s.once.Do(func() { close(s.entered) })
	select {
	case <-s.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (s *orderedHealthStore) Probe(ctx context.Context) error {
	if s.blockProbe {
		return s.wait(ctx)
	}
	return nil
}
func (s *orderedHealthStore) Count(ctx context.Context, _ Key, _ Window, _ time.Time) (CountResult, error) {
	if !s.blockProbe {
		if err := s.wait(ctx); err != nil {
			return CountResult{}, err
		}
	}
	return CountResult{}, errors.New("count partition")
}
func TestGuardHealthOrderingRejectsStaleCompletions(t *testing.T) {
	for _, blockProbe := range []bool{true, false} {
		t.Run(map[bool]string{true: "old-probe", false: "old-count"}[blockProbe], func(t *testing.T) {
			store := &orderedHealthStore{blockProbe: blockProbe, entered: make(chan struct{}), release: make(chan struct{})}
			g, err := NewGuardWithStore(GuardConfig{ID: "health", Window: time.Hour, Limit: 1}, store)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			done := make(chan error, 1)
			c := guardPolicy(t, "health")
			go func() {
				if blockProbe {
					done <- g.Probe(ctx)
				} else {
					_, err := g.Evaluate(ctx, c, policy.Event{})
					done <- err
				}
			}()
			select {
			case <-store.entered:
			case <-ctx.Done():
				t.Fatal("operation did not enter")
			}
			if blockProbe {
				d, err := g.Evaluate(ctx, c, policy.Event{})
				if err == nil || d.Status != 503 {
					t.Fatal("count did not fail closed")
				}
			} else {
				if err = g.Probe(ctx); err != nil {
					t.Fatal(err)
				}
			}
			close(store.release)
			select {
			case <-done:
			case <-ctx.Done():
				t.Fatal("old operation did not return")
			}
			ready, err := g.Ready()
			if ready == blockProbe {
				t.Fatalf("stale completion overwrote readiness: %v %v", ready, err)
			}
			if err = g.Probe(ctx); err != nil {
				t.Fatal(err)
			}
			if ready, err = g.Ready(); !ready || err != nil {
				t.Fatalf("fresh probe did not recover: %v %v", ready, err)
			}
		})
	}
}
