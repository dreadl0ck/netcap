package waf

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/apipolicy"
	"github.com/dreadl0ck/netcap/internal/policy"
)

func TestOwnedRouteReloadPinsInflightPolicyAndContract(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			close(entered)
			<-release
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer origin.Close()
	allow := routePolicy(t, "a", "", "request")
	c := apiConfig(t, config(origin.URL), map[string][]byte{"openapi.json": []byte(apiContract)}, apipolicy.Declaration{OpenAPI: "openapi.json"})
	a, b := routeFixture(t, origin.URL, "a", "a.example", "/", 1), routeFixture(t, origin.URL, "b", "b.example", "/", 1)
	a.DescriptorPath, a.DescriptorSHA256, a.APIValidateResponse = c.DescriptorPath, c.DescriptorSHA256, true
	c.DescriptorPath, c.DescriptorSHA256 = "", ""
	c.Routes = []RouteConfig{a, b}
	f, err := NewWithOptions(c, compiled(t, "enforce", "request", ""), Options{RuntimeRouteID: "a", OwnRoutePolicy: true})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	target, _ := f.RouteTarget("a")
	proxy := httptest.NewServer(f)
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
		proxy.Close()
	}()
	request := func(n string) int {
		t.Helper()
		r, _ := http.NewRequest("POST", proxy.URL+"/items?limit=2", strings.NewReader(`{"text":"safe","n":`+n+`}`))
		r.Host = "a.example"
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Required", "yes")
		resp, err := proxy.Client().Do(r)
		if err != nil {
			t.Error(err)
			return 0
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode
	}
	done := make(chan int, 1)
	go func() { done <- request("2") }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("origin not reached")
	}
	deny := routePolicy(t, "a", `Path == "/items"`, "request")
	if err := target.ActivatePolicy(deny, target.Policy().Revision()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(a.PolicyFile, []byte("invalid file must not be read"), 0600); err != nil {
		t.Fatal(err)
	}
	writeRoutePolicy(t, b.PolicyFile, routePolicy(t, "b", `Path == "/local"`, "request"))
	if err := f.ReloadRoutePolicies(); err != nil {
		t.Fatal(err)
	}
	if target.Policy().Revision() != deny.Revision() || request("2") != 403 {
		t.Fatal("reload replaced external policy")
	}
	close(release)
	if status := <-done; status != 200 {
		t.Fatalf("inflight generation lost its policy/API snapshot: %d", status)
	}
	if got := routeCall(f, "b.example", "GET", "/local", "").Code; got != 403 {
		t.Fatalf("local file reload missing: %d", got)
	}
	if !f.ready() {
		t.Fatal("retiring old child closed listener health")
	}
	if f.Operations.Status().ActiveRevision != deny.Revision() {
		t.Fatal("unrelated route changed runtime revision label")
	}
	target.SetPolicy(allow)
	before := calls.Load()
	if request("99") != 403 || calls.Load() != before {
		t.Fatal("API validation bypassed by external target/reload")
	}
	if request("2") != 200 {
		t.Fatal("valid API request failed after restoring native policy")
	}
}

func TestRouteEffectsAdmissionIsSelectedBootstrapCapability(t *testing.T) {
	c := config("http://127.0.0.1:1")
	a, b := routeFixture(t, c.Upstream, "a", "a.example", "/", 1), routeFixture(t, c.Upstream, "b", "b.example", "/", 1)
	c.Routes = []RouteConfig{a, b}
	effect := func(id string) []byte {
		bundle := policy.Bundle{Version: "1", ID: id, Mode: "enforce", Default: "allow", Rules: []policy.Rule{{ID: "effect", Expression: "true", Action: "deny", Effects: []policy.Effect{{Kind: "block_source", Target: "client", Duration: "10s", Scope: "edge"}}}}}
		raw, _ := json.Marshal(bundle)
		return raw
	}
	if err := os.WriteFile(a.PolicyFile, effect("a"), 0600); err != nil {
		t.Fatal(err)
	}
	p := compiled(t, "enforce", "request", "")
	if f, err := New(c, p); err == nil {
		f.Close()
		t.Fatal("unadmitted route effects compiled")
	}
	opts := Options{RuntimeRouteID: "a", AllowEffects: true, OwnRoutePolicy: true}
	f, err := NewWithOptions(c, p, opts)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := os.WriteFile(b.PolicyFile, effect("b"), 0600); err != nil {
		t.Fatal(err)
	}
	if f, err := NewWithOptions(c, p, opts); err == nil {
		f.Close()
		t.Fatal("effect admission leaked to another route")
	}
}

func TestRouteAttachmentReadinessStatusAndLocalAvailability(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer origin.Close()
	c := config(origin.URL)
	c.Routes = []RouteConfig{routeFixture(t, origin.URL, "a", "a.example", "/", 1), routeFixture(t, origin.URL, "b", "b.example", "/", 1)}
	f, err := NewWithOptions(c, compiled(t, "enforce", "request", ""), Options{RuntimeRouteID: "a", OwnRoutePolicy: true})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	target, _ := f.RouteTarget("a")
	var healthy atomic.Bool
	if err := target.SetReadinessCheck(healthy.Load); err != nil {
		t.Fatal(err)
	}
	status := func(want bool) {
		t.Helper()
		w := httptest.NewRecorder()
		f.AdminHandler().ServeHTTP(w, httptest.NewRequest("GET", "/status", nil))
		if f.Operations.Status().Ready != want || target.Ready() != want {
			t.Fatalf("stale attachment status: %s", w.Body.String())
		}
	}
	status(false)
	if routeCall(f, "a.example", "GET", "/", "").Code != 503 || routeCall(f, "b.example", "GET", "/", "").Code != 204 {
		t.Fatal("unready attachment gated local neighbor")
	}
	healthy.Store(true)
	status(true)
	if err := f.ReloadRoutePolicies(); err != nil {
		t.Fatal(err)
	}
	if routeCall(f, "a.example", "GET", "/", "").Code != 204 {
		t.Fatal("reload lost attachment readiness")
	}
	target.SetDraining(true)
	status(false)
	if routeCall(f, "b.example", "GET", "/", "").Code != 204 {
		t.Fatal("attachment drain reached local neighbor")
	}
	target.SetDraining(false)
	status(true)
	if target.SetReadinessCheck(func() bool { return true }) == nil {
		t.Fatal("late route readiness mutation accepted")
	}
}
