package enforcer

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func testConfig() Config {
	return Config{Token: strings.Repeat("x", 32), DryRun: true, Scope: Scope{Hook: "input", Interface: "veth0", DestinationCIDR: "10.44.0.1/32", Protocol: "tcp", Port: 443}, ProtectedCIDRs: []string{"192.0.2.0/24"}}
}
func controller(t *testing.T, c Config, b Backend) *Controller {
	t.Helper()
	x, err := New(c, b)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := x.Close(); err != nil {
			t.Error(err)
		}
	})
	return x
}

func TestConfigBoundaries(t *testing.T) {
	cases := []struct {
		name   string
		change func(*Config)
	}{
		{"token", func(c *Config) { c.Token = "" }}, {"TTL", func(c *Config) { c.MaxTTL = HardMaxTTL + time.Second }}, {"capacity", func(c *Config) { c.MaxLeases = 1001 }},
		{"hook", func(c *Config) { c.Scope.Hook = "output" }}, {"interface", func(c *Config) { c.Scope.Interface = "*" }}, {"injection", func(c *Config) { c.Scope.Interface = "a\";drop" }},
		{"destination", func(c *Config) { c.Scope.DestinationCIDR = "0.0.0.0/0" }}, {"canonical", func(c *Config) { c.Scope.DestinationCIDR = "10.44.0.1/24" }},
		{"port", func(c *Config) { c.Scope.Port = 0 }}, {"protocol", func(c *Config) { c.Scope.Protocol = "all" }}, {"protected destination", func(c *Config) { c.ProtectedCIDRs = []string{"10.0.0.0/8"} }},
		{"table injection", func(c *Config) { c.Table = "inet; flush ruleset" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := testConfig()
			tc.change(&c)
			if x, err := New(c, nil); err == nil {
				_ = x.Close()
				t.Fatal("accepted unsafe config")
			}
		})
	}
}

func TestSourceAndTTLBoundaries(t *testing.T) {
	c := controller(t, testConfig(), nil)
	for _, source := range []string{"192.0.2.1", "192.0.2.0/24", "0.0.0.0", "127.0.0.1", "224.0.0.1", "::ffff:198.51.100.1", "2001:db8::1", "198.51.100.1;drop"} {
		if _, err := c.Create(context.Background(), "bad", source, time.Minute); err == nil {
			t.Errorf("accepted %s", source)
		}
	}
	for _, ttl := range []time.Duration{0, -1, time.Millisecond, time.Second + 1, HardMaxTTL + time.Second} {
		if _, err := c.Create(context.Background(), "bad", "198.51.100.1", ttl); err == nil {
			t.Errorf("accepted TTL %s", ttl)
		}
	}
	if _, err := c.Create(context.Background(), strings.Repeat("a", 49), "198.51.100.1", time.Minute); err == nil {
		t.Fatal("accepted oversized ID")
	}
}

func TestIdempotencyAndLimits(t *testing.T) {
	cfg := testConfig()
	cfg.MaxLeases = 1
	c := controller(t, cfg, nil)
	ctx := context.Background()
	l, err := c.Create(ctx, "one", "198.51.100.1", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	again, err := c.Create(ctx, "one", l.Source, time.Minute)
	if err != nil || again != l {
		t.Fatalf("renewed or failed: %+v %v", again, err)
	}
	if _, err = c.Create(ctx, "one", "198.51.100.2", time.Minute); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	if _, err = c.Create(ctx, "duplicate", l.Source, time.Minute); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	if _, err = c.Create(ctx, "two", "198.51.100.2", time.Minute); !errors.Is(err, ErrLimit) {
		t.Fatal(err)
	}
	if err = c.Delete(ctx, "one"); err != nil {
		t.Fatal(err)
	}
	if err = c.Delete(ctx, "one"); err != nil {
		t.Fatal(err)
	}
	if _, err = c.Create(ctx, "two", "198.51.100.2", time.Minute); err != nil {
		t.Fatal(err)
	}
}

func TestHTTP(t *testing.T) {
	c := controller(t, testConfig(), nil)
	h := c.Handler()
	request := func(method, path, token, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		if token != "" {
			r.Header.Set("Authorization", token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	for _, path := range []string{"/v1/leases", "/v1/leases/a", "/unknown"} {
		if w := request("GET", path, "", ""); w.Code != 401 {
			t.Fatal(w.Code)
		}
	}
	for _, token := range []string{"Bearer wrong", "bearer " + testConfig().Token, testConfig().Token} {
		if w := request("GET", "/v1/leases", token, ""); w.Code != 401 {
			t.Fatal(w.Code)
		}
	}
	auth := "Bearer " + testConfig().Token
	for _, body := range []string{`{"id":"a","source":"198.51.100.1","ttl_seconds":60,"scope":{}}`, `{} {}`, `{"ttl_seconds":9223372036854775807}`, strings.Repeat("a", 4097)} {
		if w := request("POST", "/v1/leases", auth, body); w.Code != 400 {
			t.Fatalf("%d %s", w.Code, w.Body.String())
		}
	}
	body := `{"id":"a","source":"198.51.100.1","ttl_seconds":60}`
	w := request("POST", "/v1/leases", auth, body)
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	var first Lease
	if err := json.Unmarshal(w.Body.Bytes(), &first); err != nil {
		t.Fatal(err)
	}
	w = request("POST", "/v1/leases", auth, body)
	var second Lease
	_ = json.Unmarshal(w.Body.Bytes(), &second)
	if w.Code != 201 || first != second {
		t.Fatal("HTTP retry renewed lease")
	}
	if w = request("GET", "/v1/leases", auth, ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"id":"a"`) {
		t.Fatal(w.Body.String())
	}
	if w = request("DELETE", "/v1/leases/a", auth, ""); w.Code != 204 {
		t.Fatal(w.Code)
	}
	if w = request("PUT", "/v1/leases", auth, ""); w.Code != http.StatusMethodNotAllowed {
		t.Fatal(w.Code)
	}
}

type fakeBackend struct {
	*DryRunBackend
	failApply  bool
	failDelete bool
}

func (b *fakeBackend) Apply(ctx context.Context, l Lease) error {
	if b.failApply {
		return errors.New("executor failed")
	}
	return b.DryRunBackend.Apply(ctx, l)
}
func (b *fakeBackend) Delete(ctx context.Context, l Lease) error {
	if b.failDelete {
		return errors.New("executor failed")
	}
	return b.DryRunBackend.Delete(ctx, l)
}

func TestPersistenceReconcileAndExpiry(t *testing.T) {
	cfg := testConfig()
	cfg.DryRun = false
	cfg.StateFile = filepath.Join(t.TempDir(), "state.json")
	b := &fakeBackend{DryRunBackend: NewDryRunBackend()}
	c := controller(t, cfg, b)
	ctx := context.Background()
	l, err := c.Create(ctx, "persist", "198.51.100.1", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = New(cfg, b); err == nil {
		t.Fatal("concurrent state owner accepted")
	}
	if err = c.Close(); err != nil {
		t.Fatal(err)
	}
	// Simulate loss of kernel state; restore only the original remaining deadline.
	b.DryRunBackend = NewDryRunBackend()
	c = controller(t, cfg, b)
	ls, err := c.List(ctx)
	if err != nil || len(ls) != 1 || ls[0] != l {
		t.Fatalf("restart: %v %v", ls, err)
	}
	rogue := l
	rogue.ID = "orphan"
	rogue.Source = "198.51.100.2"
	if err = b.Apply(ctx, rogue); err != nil {
		t.Fatal(err)
	}
	if err = c.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	ls, _ = b.List(ctx)
	if len(ls) != 1 {
		t.Fatal("orphan retained")
	}
	b.failApply = true
	if _, err = c.Create(ctx, "retry", "198.51.100.3", time.Minute); err == nil {
		t.Fatal("failure hidden")
	}
	b.failApply = false
	if err = c.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	b.failDelete = true
	if err = c.Delete(ctx, "retry"); err == nil {
		t.Fatal("delete failure hidden")
	}
	b.failDelete = false
	if err = c.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	ls, _ = b.List(ctx)
	if len(ls) != 1 {
		t.Fatal("failed deletion not reconciled")
	}
	if err = c.Delete(ctx, l.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = c.Create(ctx, "short", "198.51.100.4", time.Second); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	ls, err = c.List(ctx)
	if err != nil || len(ls) != 0 {
		t.Fatalf("expired lease retained: %v %v", ls, err)
	}
	if err = c.Close(); err != nil {
		t.Fatal(err)
	}
	cfg.Scope.Port = 8443
	if _, err = New(cfg, b); err == nil {
		t.Fatal("accepted changed persistent scope")
	}
	info, err := os.Stat(cfg.StateFile)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("non-private state", err)
	}
}

func TestRestartWithoutStateAdoptsAndConcurrentLimit(t *testing.T) {
	cfg := testConfig()
	cfg.MaxLeases = 1
	b := NewDryRunBackend()
	c := controller(t, cfg, b)
	ctx := context.Background()
	var wg sync.WaitGroup
	for _, id := range []string{"one", "two", "three"} {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			_, _ = c.Create(ctx, id, "198.51.100."+map[string]string{"one": "1", "two": "2", "three": "3"}[id], time.Minute)
		}(id)
	}
	wg.Wait()
	ls, err := c.List(ctx)
	if err != nil || len(ls) != 1 {
		t.Fatal(ls, err)
	}
	_ = c.Close()
	next := controller(t, cfg, b)
	got, err := next.List(ctx)
	if err != nil || len(got) != 1 || got[0] != ls[0] {
		t.Fatal("restart lost existing lease", got, err)
	}
}

func TestDryRunCannotExecuteRealBackend(t *testing.T) {
	if _, err := New(testConfig(), &fakeBackend{DryRunBackend: NewDryRunBackend()}); err == nil {
		t.Fatal("dry-run accepted arbitrary executor")
	}
}

func TestExpiredSnapshotIsNotReplayed(t *testing.T) {
	cfg := testConfig()
	cfg.StateFile = filepath.Join(t.TempDir(), "expired.json")
	normalized, _, err := normalize(cfg)
	if err != nil {
		t.Fatal(err)
	}
	l := Lease{ID: "expired", Source: "198.51.100.1", Scope: cfg.Scope, TTLSeconds: 60, ExpiresAt: time.Now().UTC().Add(-time.Minute)}
	data, err := json.Marshal(snapshot{1, fingerprint(normalized), []Lease{l}})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(cfg.StateFile, data, 0600); err != nil {
		t.Fatal(err)
	}
	b := NewDryRunBackend()
	c := controller(t, cfg, b)
	ls, err := c.List(context.Background())
	if err != nil || len(ls) != 0 {
		t.Fatal("expired state replayed", ls, err)
	}
	if err = c.Close(); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(cfg.StateFile, []byte(`{"version":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	if x, e := New(cfg, b); e == nil {
		_ = x.Close()
		t.Fatal("corrupt snapshot accepted")
	}
}

type closingBackend struct {
	*DryRunBackend
	closes   int
	failList bool
}

func (b *closingBackend) Close() error { b.closes++; return nil }
func (b *closingBackend) List(ctx context.Context) ([]Lease, error) {
	if b.failList {
		return nil, errors.New("list failed")
	}
	return b.DryRunBackend.List(ctx)
}

func TestBackendLifetime(t *testing.T) {
	cfg := testConfig()
	cfg.DryRun = false
	a := &closingBackend{DryRunBackend: NewDryRunBackend()}
	b := &closingBackend{DryRunBackend: NewDryRunBackend()}
	first := controller(t, cfg, a)
	second := controller(t, cfg, b)
	if _, err := first.Create(context.Background(), "one", "198.51.100.1", time.Minute); err != nil {
		t.Fatal(err)
	}
	if ls, err := second.List(context.Background()); err != nil || len(ls) != 0 {
		t.Fatal("independent memory backends interfered", ls, err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if a.closes != 1 || b.closes != 0 {
		t.Fatal("incorrect backend close count", a.closes, b.closes)
	}
	broken := &closingBackend{DryRunBackend: NewDryRunBackend(), failList: true}
	if c, err := New(cfg, broken); err == nil {
		_ = c.Close()
		t.Fatal("list error ignored")
	}
	if broken.closes != 1 {
		t.Fatal("backend leaked on startup failure")
	}
}
