package waf

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/firewallstate"
)

func readinessStatus(h http.Handler, path string) int {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
	return w.Code
}

func TestReadinessCheckBootstrapAndComposition(t *testing.T) {
	f := firewall(t, config("http://127.0.0.1:1"), compiled(t, "enforce", "request", ""))
	admin := f.AdminHandler()
	if f.SetReadinessCheck(nil) == nil {
		t.Fatal("nil readiness check accepted")
	}
	var dependency atomic.Bool
	if err := f.SetReadinessCheck(dependency.Load); err != nil {
		t.Fatal(err)
	}
	if f.SetReadinessCheck(func() bool { return true }) == nil {
		t.Fatal("readiness check replaced")
	}
	if got := readinessStatus(admin, "/readyz"); got != 503 {
		t.Fatalf("uninitialized dependency ready: %d", got)
	}
	if got := readinessStatus(admin, "/livez"); got != 200 {
		t.Fatalf("dependency failure changed liveness: %d", got)
	}
	dependency.Store(true)
	if got := readinessStatus(admin, "/readyz"); got != 200 {
		t.Fatalf("healthy dependency unready: %d", got)
	}
	f.SetDraining(true)
	if got := readinessStatus(admin, "/readyz"); got != 503 {
		t.Fatalf("callback bypassed draining: %d", got)
	}
	dependency.Store(false)
	f.SetDraining(false)
	if got := readinessStatus(admin, "/readyz"); got != 503 {
		t.Fatalf("resuming traffic disabled dependency: %d", got)
	}
	dependency.Store(true)
	previous := f.Policy()
	f.current.Store(nil)
	if got := readinessStatus(admin, "/readyz"); got != 503 {
		t.Fatalf("callback bypassed missing policy: %d", got)
	}
	f.current.Store(previous)
	_ = f.Close()
	f.SetDraining(false)
	if got := readinessStatus(admin, "/readyz"); got != 503 {
		t.Fatalf("callback bypassed closed lifetime: %d", got)
	}
}

func TestReadinessCheckCannotBeInstalledAfterServing(t *testing.T) {
	for _, entry := range []string{"admin", "data", "messages", "closed"} {
		t.Run(entry, func(t *testing.T) {
			f := firewall(t, config("http://127.0.0.1:1"), compiled(t, "enforce", "request", "true"))
			switch entry {
			case "admin":
				_ = readinessStatus(f.AdminHandler(), "/readyz")
			case "data":
				_ = call(f, "")
			case "messages":
				h, err := f.MessageHandler(false, true)
				if err != nil {
					t.Fatal(err)
				}
				r := httptest.NewRequest("POST", "https://route.example/service/method", nil)
				r.ProtoMajor = 2
				r.Header.Set("Content-Type", "application/grpc")
				h.ServeHTTP(httptest.NewRecorder(), r)
			case "closed":
				_ = f.Close()
			}
			if f.SetReadinessCheck(func() bool { return true }) == nil {
				t.Fatal("late readiness check accepted")
			}
		})
	}
}

func TestReadinessCheckConcurrentCachedTransitions(t *testing.T) {
	f := firewall(t, config("http://127.0.0.1:1"), compiled(t, "enforce", "request", ""))
	var dependency atomic.Bool
	if err := f.SetReadinessCheck(dependency.Load); err != nil {
		t.Fatal(err)
	}
	admin := f.AdminHandler()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for n := 0; n < 100; n++ {
				dependency.Store((i+n)%2 == 0)
				if status := readinessStatus(admin, "/readyz"); status != 200 && status != 503 {
					t.Errorf("invalid readiness status: %d", status)
				}
			}
		}(i)
	}
	wg.Wait()
}

func privateState(t *testing.T) (*firewallstate.Service, *httptest.Server, *atomic.Bool, *atomic.Int64) {
	t.Helper()
	service, err := firewallstate.New(firewallstate.Config{StateDir: filepath.Join(t.TempDir(), "state"), Principals: []firewallstate.Principal{{ID: "agent", Token: strings.Repeat("t", 32), Scope: firewallstate.Scope{Tenant: "tenant", App: "app"}}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	failing := &atomic.Bool{}
	calls := &atomic.Int64{}
	handler := service.Handler()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if failing.Load() {
			http.Error(w, "offline", 503)
			return
		}
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	return service, server, failing, calls
}

func testSharedGuard(t *testing.T, server *httptest.Server) *firewallstate.Guard {
	t.Helper()
	g, err := firewallstate.NewGuard(firewallstate.GuardConfig{URL: server.URL, Token: strings.Repeat("t", 32), ID: "rate", Window: time.Minute, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestSharedGuardReadinessStartupFailureRecoveryAndNoProbeIO(t *testing.T) {
	_, state, failing, calls := privateState(t)
	guard := testSharedGuard(t, state)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer origin.Close()
	f := firewall(t, config(origin.URL), compiled(t, "enforce", "request", ""))
	if err := f.SetEvaluator(guard.Evaluate); err != nil {
		t.Fatal(err)
	}
	var fleetReady atomic.Bool
	fleetReady.Store(true)
	if err := f.SetReadinessCheck(func() bool { ready, err := guard.Ready(); return err == nil && ready && fleetReady.Load() }); err != nil {
		t.Fatal(err)
	}
	admin := f.AdminHandler()
	probe := func(want int) {
		t.Helper()
		before := calls.Load()
		for i := 0; i < 5; i++ {
			if got := readinessStatus(admin, "/readyz"); got != want {
				t.Fatalf("readyz=%d want=%d", got, want)
			}
		}
		if calls.Load() != before {
			t.Fatal("readiness probe performed shared-state I/O")
		}
	}
	probe(503)
	if calls.Load() != 0 {
		t.Fatal("startup readiness contacted shared state")
	}
	if w := call(f, ""); w.Code != 200 {
		t.Fatalf("healthy admission: %d", w.Code)
	}
	probe(200)
	fleetReady.Store(false)
	probe(503)
	fleetReady.Store(true)
	probe(200)
	failing.Store(true)
	if w := call(f, ""); w.Code != 503 {
		t.Fatalf("failed guard admission: %d", w.Code)
	}
	probe(503)
	f.SetDraining(true)
	f.SetDraining(false)
	fleetReady.Store(true)
	probe(503)
	failing.Store(false)
	probe(503)
	if w := call(f, ""); w.Code != 200 {
		t.Fatalf("recovered admission: %d", w.Code)
	}
	probe(200)
	if calls.Load() != 3 {
		t.Fatalf("admissions/probes changed shared count requests: %d", calls.Load())
	}
}

func TestDefaultRequestGuardCountsUnaryHTTP2Once(t *testing.T) {
	service, state, _, calls := privateState(t)
	guard := testSharedGuard(t, state)
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Error("upstream was not HTTP/2")
		}
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status")
		_, _ = w.Write(rpcWire("reply"))
		w.Header().Set("Grpc-Status", "0")
	}))
	origin.EnableHTTP2 = true
	origin.StartTLS()
	defer origin.Close()
	p := compiled(t, "enforce", "request", "")
	f := firewall(t, config(origin.URL), p)
	f.transport.TLSClientConfig = origin.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	if err := f.SetEvaluator(guard.Evaluate); err != nil {
		t.Fatal(err)
	}
	if err := f.SetReadinessCheck(func() bool { ready, err := guard.Ready(); return ready && err == nil }); err != nil {
		t.Fatal(err)
	}
	handler, err := f.MessageHandler(false, true)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewUnstartedServer(handler)
	proxy.EnableHTTP2 = true
	proxy.StartTLS()
	defer proxy.Close()
	admin := f.AdminHandler()
	if readinessStatus(admin, "/readyz") != 503 {
		t.Fatal("uncontacted guard ready")
	}
	req, _ := http.NewRequest("POST", proxy.URL+"/service/Unary", bytes.NewReader(rpcWire("request")))
	req.Header.Set("Content-Type", "application/grpc")
	resp, err := proxy.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil || resp.ProtoMajor != 2 || resp.StatusCode != 200 || !bytes.Equal(data, rpcWire("reply")) || resp.Trailer.Get("Grpc-Status") != "0" {
		t.Fatalf("unary response: proto=%s status=%d data=%x error=%v", resp.Proto, resp.StatusCode, data, err)
	}
	if calls.Load() != 1 || readinessStatus(admin, "/readyz") != 200 || calls.Load() != 1 {
		t.Fatalf("unary/probe used more than one shared request unit: %d", calls.Load())
	}
	key := firewallstate.Key{Revision: p.Revision(), Group: firewallstate.Digest("rate\x00request\x00\x00")}
	count, err := service.Bind(firewallstate.Scope{Tenant: "tenant", App: "app"}).Count(context.Background(), key, firewallstate.Window{Mode: "fixed", Duration: time.Minute}, time.Now())
	if err != nil || count.Count != 2 {
		t.Fatalf("persisted unary request units: next=%d error=%v", count.Count, err)
	}
}
