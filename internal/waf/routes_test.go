package waf

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/policy"
)

func routePolicy(t *testing.T, id, expression, phase string) *policy.Compiled {
	t.Helper()
	b := policy.Bundle{Version: "v1", ID: id, Mode: "enforce", Default: "allow"}
	if expression != "" {
		b.Rules = []policy.Rule{{ID: "deny", Phase: phase, Expression: expression, Action: "deny", Status: 403}}
	}
	p, err := policy.Compile(b)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func writeRoutePolicy(t *testing.T, file string, p *policy.Compiled) {
	t.Helper()
	b, err := json.Marshal(p.Bundle())
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(file, b, 0600); err != nil {
		t.Fatal(err)
	}
}
func routeFixture(t *testing.T, origin, id, host, prefix string, priority int) RouteConfig {
	t.Helper()
	file := filepath.Join(t.TempDir(), "policy.json")
	writeRoutePolicy(t, file, routePolicy(t, id, "", "request"))
	return RouteConfig{ID: id, PolicyID: id, PolicyFile: file, Priority: priority, Hosts: []string{host}, Methods: []string{"GET", "POST"}, PathPrefix: prefix, Upstream: origin, MaxBodyBytes: 1024, MaxResponseBytes: 1024, MaxConcurrent: 8}
}
func routeCall(f *Firewall, host, method, p, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://"+host+p, strings.NewReader(body))
	w := httptest.NewRecorder()
	f.ServeHTTP(w, r)
	return w
}

func TestRouteHostMethodPathIsolation(t *testing.T) {
	var callsA, callsB atomic.Int64
	origin := func(name string, calls *atomic.Int64) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			_, _ = fmt.Fprintf(w, "%s|%s|%s", name, r.Host, r.URL.Path)
		}))
	}
	a, b := origin("A", &callsA), origin("B", &callsB)
	defer a.Close()
	defer b.Close()
	c := config("http://unused.invalid")
	c.Routes = []RouteConfig{routeFixture(t, a.URL, "a", "a.example", "/api", 1), routeFixture(t, b.URL, "b", "b.example", "/", 1), routeFixture(t, b.URL, "admin", "a.example", "/api/admin", 10)}
	writeRoutePolicy(t, c.Routes[2].PolicyFile, routePolicy(t, "admin", `Path contains "admin"`, "request"))
	f := firewall(t, c, compiled(t, "enforce", "request", ""))
	// Mutating the caller's routing inputs must not retarget the live listener.
	c.Routes[0].Hosts[0] = "evil.example"
	for _, tc := range []struct {
		host, method, path, body string
		status                   int
		response                 string
	}{
		{"a.example", "GET", "/api", "", 200, "A|a.example|/api"},
		{"a.example", "GET", "/api/", "", 200, "A|a.example|/api/"},
		{"A.EXAMPLE", "POST", "/api/child", "", 200, "A|A.EXAMPLE|/api/child"},
		{"b.example", "GET", "/", "", 200, "B|b.example|/"},
		{"unknown.example", "GET", "/api", "", 421, ""},
		{"a.example:80", "GET", "/api", "", 421, ""},
		{"a.example", "DELETE", "/api", "", 404, ""},
		{"a.example", "get", "/api", "", 404, ""},
		{"a.example", "GET", "/apix", "", 404, ""},
		{"a.example", "GET", "/api/admin", "", 403, ""},
		{"a.example", "GET", "/api/../api/admin", "", 400, ""},
		{"a.example", "GET", "/api%2fadmin", "", 400, ""},
		{"a.example", "POST", "/api", strings.Repeat("x", 1025), 413, ""},
	} {
		t.Run(tc.host+tc.method+tc.path, func(t *testing.T) {
			before := callsA.Load() + callsB.Load()
			w := routeCall(f, tc.host, tc.method, tc.path, tc.body)
			if w.Code != tc.status {
				t.Fatalf("got %d want %d", w.Code, tc.status)
			}
			if tc.response != "" && w.Body.String() != tc.response {
				t.Fatal(w.Body.String())
			}
			if tc.status != 200 && callsA.Load()+callsB.Load() != before {
				t.Fatal("denied request reached origin")
			}
		})
	}
	f.SetPolicy(compiled(t, "enforce", "request", `Method == "GET"`))
	if w := routeCall(f, "b.example", "GET", "/", ""); w.Code != 200 {
		t.Fatal("global policy crossed route binding", w.Code)
	}
}

func TestRouteValidationAndAtomicReload(t *testing.T) {
	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer a.Close()
	c := config(a.URL)
	c.Routes = []RouteConfig{routeFixture(t, a.URL, "a", "a.example", "/", 0), routeFixture(t, a.URL, "b", "b.example", "/", 0)}
	for _, mutate := range []func(*Config){
		func(c *Config) { c.Routes[1].Hosts = []string{"a.example"} },
		func(c *Config) { c.Routes[1].PathPrefix = "/../escape" },
		func(c *Config) { c.Routes[1].Hosts = []string{"*.example"} },
		func(c *Config) { c.Routes[1].Upstream = "http://origin/path" },
	} {
		copy := c
		copy.Routes = append([]RouteConfig(nil), c.Routes...)
		mutate(&copy)
		if ValidateConfig(copy) == nil {
			t.Fatal("invalid route accepted")
		}
	}
	f := firewall(t, c, compiled(t, "enforce", "request", ""))
	writeRoutePolicy(t, c.Routes[0].PolicyFile, routePolicy(t, "a", `Method == "GET"`, "request"))
	writeRoutePolicy(t, c.Routes[1].PolicyFile, routePolicy(t, "a", "", "request"))
	if f.ReloadRoutePolicies() == nil {
		t.Fatal("cross-identity reload accepted")
	}
	if w := routeCall(f, "a.example", "GET", "/", ""); w.Code != 200 {
		t.Fatal("partial reload activated", w.Code)
	}
	writeRoutePolicy(t, c.Routes[1].PolicyFile, routePolicy(t, "b", `Method == "GET"`, "request"))
	if err := f.ReloadRoutePolicies(); err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"a.example", "b.example"} {
		if w := routeCall(f, host, "GET", "/", ""); w.Code != 403 {
			t.Fatal("reload missing", host, w.Code)
		}
	}
	target, err := f.RouteTarget("a")
	if err != nil {
		t.Fatal(err)
	}
	if err = target.ActivatePolicy(routePolicy(t, "b", "", "request"), target.Policy().Revision()); err == nil {
		t.Fatal("cross-tenant activation")
	}
	if err = target.ActivatePolicy(routePolicy(t, "a", "", "request"), target.Policy().Revision()); err != nil {
		t.Fatal(err)
	}
	if err = target.ActivatePolicy(routePolicy(t, "a", `Method == "GET"`, "request"), "stale-revision"); err == nil {
		t.Fatal("stale route activation accepted")
	}
	if routeCall(f, "a.example", "GET", "/", "").Code != 200 || routeCall(f, "b.example", "GET", "/", "").Code != 403 {
		t.Fatal("activation escaped route")
	}
	if _, err = f.RouteTarget("../../policy"); err == nil {
		t.Fatal("path admitted as target")
	}
}

func TestRouteLateBodyDenyAcrossRealListeners(t *testing.T) {
	var calls atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
	}))
	defer origin.Close()
	c := config(origin.URL)
	c.Routes = []RouteConfig{routeFixture(t, origin.URL, "a", "a.example", "/", 0)}
	c.Routes[0].MaxBodyBytes = 1 << 20
	writeRoutePolicy(t, c.Routes[0].PolicyFile, routePolicy(t, "a", `Body contains "late-deny"`, "request"))
	f := firewall(t, c, compiled(t, "enforce", "request", ""))
	proxy := httptest.NewServer(f)
	defer proxy.Close()
	reader, writer := io.Pipe()
	req, _ := http.NewRequest("POST", proxy.URL, reader)
	req.Host = "a.example"
	done := make(chan error, 1)
	go func() {
		resp, err := proxy.Client().Do(req)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode != 403 {
				err = fmt.Errorf("late body status %d", resp.StatusCode)
			}
		}
		done <- err
	}()
	if _, err := io.WriteString(writer, strings.Repeat("x", 256<<10)); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 0 {
		t.Fatal("partial body reached origin")
	}
	_, _ = io.WriteString(writer, "late-deny")
	_ = writer.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("late body request stalled")
	}
	if calls.Load() != 0 {
		t.Fatal("denied late body reached origin")
	}
}

func TestRouteConcurrencySurvivesReloadAndIsolatesMethods(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		_, _ = io.WriteString(w, "A")
	}))
	defer a.Close()
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "B") }))
	defer b.Close()
	c := config(a.URL)
	c.Routes = []RouteConfig{routeFixture(t, a.URL, "a", "a.example", "/", 0), routeFixture(t, b.URL, "b", "a.example", "/", 0)}
	c.Routes[0].Methods, c.Routes[1].Methods = []string{"GET"}, []string{"POST"}
	c.Routes[0].MaxConcurrent = 1
	f := firewall(t, c, compiled(t, "enforce", "request", ""))
	done := make(chan int, 1)
	go func() { done <- routeCall(f, "a.example", "GET", "/", "").Code }()
	<-entered
	defer func() { close(release); <-done }()
	if err := f.ReloadRoutePolicies(); err != nil {
		t.Fatal(err)
	}
	if w := routeCall(f, "a.example", "GET", "/", ""); w.Code != 503 {
		t.Fatalf("reload bypassed route limit: %d", w.Code)
	}
	if w := routeCall(f, "a.example", "POST", "/", ""); w.Code != 200 || w.Body.String() != "B" {
		t.Fatalf("method route isolated incorrectly: %d %s", w.Code, w.Body.String())
	}
}

func TestRouteResponsePinsPolicyDuringReload(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		_, _ = io.WriteString(w, "secret")
	}))
	defer a.Close()
	c := config(a.URL)
	c.InspectResponse = true
	c.Routes = []RouteConfig{routeFixture(t, a.URL, "a", "a.example", "/", 0)}
	writeRoutePolicy(t, c.Routes[0].PolicyFile, routePolicy(t, "a", `Body contains "secret"`, "response"))
	f := firewall(t, c, compiled(t, "enforce", "request", ""))
	done := make(chan int, 1)
	go func() { done <- routeCall(f, "a.example", "GET", "/", "").Code }()
	<-entered
	writeRoutePolicy(t, c.Routes[0].PolicyFile, routePolicy(t, "a", "", "request"))
	if err := f.ReloadRoutePolicies(); err != nil {
		t.Fatal(err)
	}
	close(release)
	if status := <-done; status != 403 {
		t.Fatal("response changed pinned policy", status)
	}
	f.routeMu.Lock()
	defer f.routeMu.Unlock()
	if len(f.retired) != 0 {
		t.Fatal("completed route generation retained")
	}
}

func TestRouteConcurrentActivationAndReload(t *testing.T) {
	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer a.Close()
	c := config(a.URL)
	c.Routes = []RouteConfig{routeFixture(t, a.URL, "a", "a.example", "/", 0)}
	f := firewall(t, c, compiled(t, "enforce", "request", ""))
	target, _ := f.RouteTarget("a")
	allow, deny := routePolicy(t, "a", "", "request"), routePolicy(t, "a", `Method == "GET"`, "request")
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 30; j++ {
				w := routeCall(f, "a.example", "GET", "/", "")
				if w.Code != 200 && w.Code != 403 {
					t.Errorf("status %d", w.Code)
				}
			}
		}()
	}
	for i := 0; i < 10; i++ {
		if err := target.ActivatePolicy(deny, target.Policy().Revision()); err != nil {
			t.Fatal(err)
		}
		if err := f.ReloadRoutePolicies(); err != nil {
			t.Fatal(err)
		}
		if err := target.ActivatePolicy(allow, target.Policy().Revision()); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
}
