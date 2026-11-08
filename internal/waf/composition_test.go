package waf

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/internal/apipolicy"
	"github.com/dreadl0ck/netcap/internal/policy"
	"github.com/dreadl0ck/netcap/internal/policycontrol"
)

func composedFirewall(t *testing.T, c Config, p *policy.Compiled, routed bool) (*Firewall, *Firewall, http.Handler) {
	t.Helper()
	if !routed {
		f := firewall(t, c, p)
		return f, f, f
	}
	r := routeFixture(t, c.Upstream, p.Bundle().ID, "api.example", "/", 1)
	writeRoutePolicy(t, r.PolicyFile, p)
	r.MaxBodyBytes, r.MaxResponseBytes, r.MaxConcurrent = c.MaxBodyBytes, c.MaxResponseBytes, c.MaxConcurrent
	r.DescriptorPath, r.DescriptorSHA256, r.APIValidateResponse = c.DescriptorPath, c.DescriptorSHA256, c.APIValidateResponse
	r.UpstreamCA, r.UpstreamCert, r.UpstreamKey = c.UpstreamCA, c.UpstreamCert, c.UpstreamKey
	if strings.HasPrefix(c.Upstream, "https:") {
		r.UpstreamServerName = "example.com"
	}
	c.DescriptorPath, c.DescriptorSHA256, c.APIValidateResponse = "", "", false
	c.Routes = []RouteConfig{r}
	f, err := NewWithOptions(c, p, Options{RuntimeRouteID: r.ID, OwnRoutePolicy: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Host = "api.example"
		f.ServeHTTP(w, r)
	})
	return f, f.router.current.Load().bindings[0].firewall, h
}

func TestRouteManagedTargetAdmissionRecoveryAndIsolation(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer origin.Close()
	c := config(origin.URL)
	c.Routes = []RouteConfig{routeFixture(t, origin.URL, "a", "a.example", "/", 1), routeFixture(t, origin.URL, "b", "b.example", "/", 1)}
	f := firewall(t, c, compiled(t, "enforce", "request", ""))
	target, err := f.RouteTarget("a")
	if err != nil {
		t.Fatal(err)
	}
	cfg := policycontrol.Config{Token: strings.Repeat("synthetic-", 4), Managed: true, StateDir: filepath.Join(t.TempDir(), "control")}
	s, err := policycontrol.New(cfg, target)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	bad, _ := json.Marshal(routePolicy(t, "b", "true", "request").Bundle())
	if _, err := s.Execute(t.Context(), "stage", policycontrol.Request{Bundle: string(bad), IdempotencyKey: "foreign"}); err == nil {
		t.Fatal("foreign route policy admitted")
	}
	deny := routePolicy(t, "a", `Method == "POST"`, "request")
	raw, _ := json.Marshal(deny.Bundle())
	if _, err := s.Execute(t.Context(), "stage", policycontrol.Request{Bundle: string(raw), IdempotencyKey: "stage"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Execute(t.Context(), "activate", policycontrol.Request{Revision: deny.Revision(), ExpectedRevision: target.Policy().Revision(), IdempotencyKey: "activate"}); err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"a.example", "b.example"} {
		want := 204
		if host == "a.example" {
			want = 403
		}
		if got := routeCall(f, host, "POST", "/", "").Code; got != want {
			t.Fatalf("%s status=%d want=%d", host, got, want)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	target.SetPolicy(routePolicy(t, "a", "", "request"))
	recovered, err := policycontrol.New(cfg, target)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	if target.Policy().Revision() != deny.Revision() || routeCall(f, "b.example", "POST", "/", "").Code != 204 {
		t.Fatal("restart lost route ownership")
	}
	if err := recovered.Close(); err != nil {
		t.Fatal(err)
	}
	foreign, _ := f.RouteTarget("b")
	if unexpected, err := policycontrol.New(cfg, foreign); err == nil {
		unexpected.Close()
		t.Fatal("state directory recovered across route identities")
	}
}

func TestRoutedNestedUnknownFieldsRejected(t *testing.T) {
	c := config("http://127.0.0.1:1")
	c.Routes = []RouteConfig{routeFixture(t, c.Upstream, "a", "a.example", "/", 1)}
	raw, _ := json.Marshal(c)
	for _, needle := range []string{`"policyID":"a"`, `"id":"a"`} {
		bad := strings.Replace(string(raw), needle, needle+`,"untrustedDescriptor":true`, 1)
		if _, err := LoadConfig([]byte(bad)); err == nil {
			t.Fatal("unknown nested route field accepted")
		}
	}
}

func TestRouteContractsNeverFallBackAcrossBindings(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer origin.Close()
	c := apiConfig(t, config(origin.URL), map[string][]byte{"openapi.json": []byte(apiContract)}, apipolicy.Declaration{OpenAPI: "openapi.json"})
	a, b := routeFixture(t, origin.URL, "a", "a.example", "/", 1), routeFixture(t, origin.URL, "b", "b.example", "/", 1)
	a.DescriptorPath, a.DescriptorSHA256 = c.DescriptorPath, c.DescriptorSHA256
	c.DescriptorPath, c.DescriptorSHA256 = "", ""
	c.Routes = []RouteConfig{a, b}
	f := firewall(t, c, compiled(t, "enforce", "request", ""))
	if got := routeCall(f, "a.example", "GET", "/unknown", "").Code; got != 403 {
		t.Fatalf("contract route status=%d", got)
	}
	if got := routeCall(f, "b.example", "GET", "/unknown", "").Code; got != 204 {
		t.Fatalf("contract leaked across route status=%d", got)
	}
	c.DescriptorPath, c.DescriptorSHA256 = a.DescriptorPath, a.DescriptorSHA256
	if ValidateConfig(c) == nil {
		t.Fatal("ambiguous global contract accepted with routes")
	}
}
