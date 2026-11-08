package waf

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/apipolicy"
	"github.com/dreadl0ck/netcap/internal/firewallstate"
	"github.com/dreadl0ck/netcap/internal/policy"
	"github.com/dreadl0ck/netcap/internal/policystate"
)

func TestRoutedNativeResponseAuthorityBodySemantics(t *testing.T) {
	for _, tc := range []struct {
		name, method       string
		status             int
		inspect, api, deny bool
		failure            string
	}{
		{name: "metadata", method: "GET", status: 200},
		{name: "buffered", method: "GET", status: 200, inspect: true},
		{name: "empty-200", method: "GET", status: 200, inspect: true},
		{name: "no-content", method: "GET", status: 204},
		{name: "not-modified", method: "GET", status: 304},
		{name: "head", method: "HEAD", status: 200, inspect: true},
		{name: "api-body", method: "GET", status: 200, api: true},
		{name: "api-head", method: "HEAD", status: 200, api: true},
		{name: "api-no-content", method: "GET", status: 204, api: true},
		{name: "api-not-modified", method: "GET", status: 304, api: true},
		{name: "response-deny-buffered", method: "GET", status: 200, inspect: true, deny: true},
		{name: "response-deny-bodyless", method: "GET", status: 204, deny: true},
		{name: "response-deny-head-api", method: "HEAD", status: 200, api: true, deny: true},
		{name: "authority-unavailable", method: "GET", status: 200, inspect: true, failure: "unavailable"},
		{name: "authority-invalid-decision", method: "GET", status: 204, failure: "revision"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const token = "native-response-fixture-token-32-bytes"
			s, err := policystate.New(policystate.Config{StateDir: filepath.Join(t.TempDir(), "state"), Principals: []policystate.Principal{{ID: "proxy", Token: token, Scope: firewallstate.Scope{Tenant: "tenant-a", App: "app-a"}}}})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			var mu sync.Mutex
			var events []policy.Event
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				raw, _ := io.ReadAll(r.Body)
				r.Body = io.NopCloser(bytes.NewReader(raw))
				var input policystate.Request
				_ = json.Unmarshal(raw, &input)
				if input.Event != nil {
					mu.Lock()
					events = append(events, *input.Event)
					mu.Unlock()
					if input.Event.Phase == "response" && tc.failure == "unavailable" {
						http.Error(w, "fixture unavailable", 503)
						return
					}
				}
				record := httptest.NewRecorder()
				s.Handler().ServeHTTP(record, r)
				if record.Code != 200 {
					t.Errorf("native authority HTTP %d: %s", record.Code, record.Body.String())
				}
				for k, v := range record.Header() {
					w.Header()[k] = v
				}
				w.WriteHeader(record.Code)
				if input.Event != nil && input.Event.Phase == "response" && tc.failure == "revision" {
					var d policy.Decision
					_ = json.Unmarshal(record.Body.Bytes(), &d)
					d.Revision = strings.Repeat("0", 64)
					_ = json.NewEncoder(w).Encode(d)
					return
				}
				_, _ = w.Write(record.Body.Bytes())
			}))
			defer server.Close()
			authority, err := policystate.NewClient(policystate.ClientConfig{URL: server.URL, Token: token})
			if err != nil {
				t.Fatal(err)
			}
			defer authority.Close()
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if tc.status == 200 && tc.name != "empty-200" {
					w.Header().Set("Content-Length", "11")
				}
				w.WriteHeader(tc.status)
				if tc.status == 200 && tc.name != "empty-200" {
					_, _ = io.WriteString(w, `{"ok":true}`)
				}
			}))
			defer origin.Close()
			c := config(origin.URL)
			c.InspectResponse = tc.inspect
			route := routeFixture(t, origin.URL, "a", "a.example", "/", 1)
			route.Methods = []string{"GET", "HEAD"}
			if tc.api {
				op := fmt.Sprintf(`{"responses":{"%d":{"description":"fixture","content":{"application/json":{"schema":{"type":"object","required":["ok"],"properties":{"ok":{"const":true}}}}}}}}`, tc.status)
				doc := `{"openapi":"3.1.0","info":{"title":"fixture","version":"1"},"paths":{"/items":{"get":` + op + `,"head":` + op + `}}}`
				c = apiConfig(t, c, map[string][]byte{"openapi.json": []byte(doc)}, apipolicy.Declaration{OpenAPI: "openapi.json"})
				route.DescriptorPath, route.DescriptorSHA256, route.APIValidateResponse = c.DescriptorPath, c.DescriptorSHA256, true
				c.DescriptorPath, c.DescriptorSHA256 = "", ""
			}
			p := routePolicy(t, "a", "", "request")
			if tc.deny {
				p, err = policy.Compile(policy.Bundle{Version: "1", ID: "a", Mode: "enforce", Default: "allow", Rules: []policy.Rule{{ID: "response", Phase: "response", Action: "deny", Status: 451, Expression: fmt.Sprintf("Status == %d", tc.status)}}})
				if err != nil {
					t.Fatal(err)
				}
			}
			writeRoutePolicy(t, route.PolicyFile, p)
			c.Routes = []RouteConfig{route}
			f, err := NewWithOptions(c, p, Options{RuntimeRouteID: "a", OwnRoutePolicy: true})
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			if err := f.SetEvaluator(func(ctx context.Context, p *policy.Compiled, e policy.Event) (policy.Decision, error) {
				if BoundRouteID(ctx) != "a" {
					t.Error("lost trusted route context")
				}
				d, err := authority.Evaluate(ctx, p, e)
				if err != nil {
					return policy.Decision{Verdict: "deny", Status: 503, Revision: p.Revision()}, err
				}
				return d, nil
			}); err != nil {
				t.Fatal(err)
			}
			proxy := httptest.NewServer(f)
			defer proxy.Close()
			req, _ := http.NewRequest(tc.method, proxy.URL+"/items", nil)
			req.Host = "a.example"
			req.Header.Set("X-Route-ID", "b")
			resp, err := proxy.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			want := tc.status
			if tc.deny {
				want = 451
			}
			if tc.failure != "" {
				want = 503
			}
			if err != nil || resp.StatusCode != want {
				t.Fatalf("status=%d want=%d body=%q err=%v", resp.StatusCode, want, body, err)
			}
			if want != tc.status && bytes.Contains(body, []byte(`"ok"`)) {
				t.Fatal("rejected origin body leaked")
			}
			if tc.method == "HEAD" || want == 204 || want == 304 {
				if len(body) != 0 {
					t.Fatalf("bodyless response leaked %q", body)
				}
			}
			mu.Lock()
			defer mu.Unlock()
			if len(events) != 2 || events[0].Phase != "request" || events[1].Phase != "response" || events[1].Status != tc.status || events[0].ClientIP != "127.0.0.1" || events[1].ClientIP != events[0].ClientIP {
				t.Fatalf("authority events=%+v", events)
			}
		})
	}
}

type responseRoundTripper func(*http.Request) (*http.Response, error)

func (f responseRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestOriginBodyCancellationPreservesInspectionLifetime(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", "http://origin.invalid/", nil)
	var forwarding context.Context
	transport := headerDeadlineTransport{timeout: time.Second, base: responseRoundTripper(func(r *http.Request) (*http.Response, error) {
		forwarding = r.Context()
		return &http.Response{StatusCode: 204, Request: r, Body: io.NopCloser(strings.NewReader(""))}, nil
	})}
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if forwarding.Err() != context.Canceled || resp.Request.Context().Err() != nil {
		t.Fatal("origin close canceled response inspection")
	}
	cancel()
	if resp.Request.Context().Err() != context.Canceled {
		t.Fatal("real client cancellation was detached")
	}
}
