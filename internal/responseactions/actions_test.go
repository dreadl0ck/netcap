package responseactions

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/enforcer"
	"github.com/dreadl0ck/netcap/internal/policy"
)

func typedIntent(kind, profile string) policy.Intent {
	i := intent("192.0.2.5")
	i.Kind = kind
	i.Profile = profile
	i.ID = policy.IntentID(i)
	return i
}

func TestProfileVerificationPrecedesMutationAndFlowAttribution(t *testing.T) {
	profiles := map[string]enforcer.Profile{"isolate": {Kind: enforcer.Quarantine, Services: []enforcer.Service{{Protocol: "tcp", Port: 443}, {Protocol: "udp", Port: 53}}}}
	c, err := enforcer.New(enforcer.Config{Token: strings.Repeat("t", 32), Scope: testScope, Profiles: profiles, DryRun: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var posts atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/leases" && r.Method == "POST" {
			posts.Add(1)
		}
		c.Handler().ServeHTTP(w, r)
	}))
	defer server.Close()
	cfg := configFor(t, server)
	s := cfg.Scopes["edge"]
	s.Profiles = profiles
	cfg.Scopes["edge"] = s
	b := newBroker(t, cfg)
	i := typedIntent("quarantine", "isolate")
	if r := b.Submit(i, i.Source); r.Status != "requested" {
		t.Fatal(r)
	}
	await(t, b, i.ID, "simulated")
	// The remote profile is unchanged while the broker has a different bootstrap authority.
	badCfg := configFor(t, server)
	s = badCfg.Scopes["edge"]
	s.Profiles = map[string]enforcer.Profile{"isolate": {Kind: enforcer.Quarantine, Services: []enforcer.Service{{Protocol: "tcp", Port: 444}}}}
	badCfg.Scopes["edge"] = s
	bad := newBroker(t, badCfg)
	before := posts.Load()
	i = typedIntent("quarantine", "isolate")
	bad.Submit(i, i.Source)
	if r := await(t, bad, i.ID, "failed"); r.Reason != "profile-mismatch" || posts.Load() != before {
		t.Fatalf("mutation before scope verification: %+v posts=%d", r, posts.Load())
	}
	f := enforcer.Flow{Destination: "198.51.100.1", Protocol: "tcp", SourcePort: 12345, DestinationPort: 443}
	i = typedIntent("drop_flow", "")
	i.Target = "source"
	i.Flow = f
	i.ID = policy.IntentID(i)
	if r := b.Submit(i, i.Source); r.Status != "failed" {
		t.Fatal("source-only attribution authorized flow", r)
	}
	wrong := f
	wrong.SourcePort++
	if r := b.SubmitFlow(i, i.Source, &wrong); r.Status != "failed" {
		t.Fatal("mismatched trusted tuple authorized", r)
	}
	// Use another source to avoid overlap with the earlier quarantine.
	i.Source = "192.0.2.6"
	i.ID = policy.IntentID(i)
	if r := b.SubmitFlow(i, i.Source, &f); r.Status != "requested" {
		t.Fatal(r)
	}
	await(t, b, i.ID, "simulated")
	ls, err := c.List(context.Background())
	if err != nil || len(ls) != 2 {
		t.Fatalf("typed actions: %+v %v", ls, err)
	}
}

func TestBoundedNotificationsPartialFailureAndNoEmit(t *testing.T) {
	var calls atomic.Int32
	sink := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/configured" || r.Header.Get("Authorization") != "Bearer "+strings.Repeat("t", 32) {
			t.Error("sink routing/auth changed")
		}
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 4097))
		if len(raw) > 4096 || strings.Contains(string(raw), "secret-body") {
			t.Error("unbounded event data sent")
		}
		var i policy.Intent
		if json.Unmarshal(raw, &i) != nil || i.ID != r.Header.Get("Idempotency-Key") {
			t.Error("missing notification identity")
		}
		w.WriteHeader(204)
	}))
	defer sink.Close()
	cfg := configFor(t, sink)
	s := cfg.Scopes["edge"]
	s.Notification = true
	s.NotificationPath = "/configured"
	cfg.Scopes["edge"] = s
	b := newBroker(t, cfg)
	i := typedIntent("notify", "")
	if r := b.Submit(i, i.Source); r.Status != "requested" {
		t.Fatal(r)
	}
	await(t, b, i.ID, "notified")
	if r := b.Submit(i, i.Source); r.Status != "duplicate" {
		t.Fatal(r)
	}
	if calls.Load() != 1 {
		t.Fatal("notification retried")
	}
	bad := typedIntent("block_source", "")
	b.Submit(bad, bad.Source)
	if status, rs := b.Batch([]string{i.ID, bad.ID}); status != "partial-failed" || len(rs) != 2 {
		t.Fatalf("partial delivery reported as %s: %+v", status, rs)
	}
	if status, _ := b.Batch([]string{"missing"}); status != "unknown" {
		t.Fatal(status)
	}
	// All typed effects remain inert in monitor and replay, including notifications.
	for _, mode := range []string{"monitor", "enforce"} {
		for _, kind := range []string{"notify", "block_source", "quarantine", "rate_source", "redirect_source", "drop_flow", "reject_flow"} {
			profile, target := "", "client"
			if kind == "quarantine" || kind == "rate_source" || kind == "redirect_source" {
				profile = "operator"
			}
			if strings.HasSuffix(kind, "_flow") {
				target = "source"
			}
			p, err := policy.CompileWithOptions(policy.Bundle{Version: "1", ID: "no-emit", Mode: mode, Default: "allow", Rules: []policy.Rule{{ID: "rule", Action: "deny", Expression: "true", Effects: []policy.Effect{{Kind: kind, Profile: profile, Target: target, Scope: "edge", Duration: "10s"}}}}}, policy.CompileOptions{AllowEffects: true})
			if err != nil {
				t.Fatal(err)
			}
			e := Evaluator{Policy: p, Broker: b, Replay: mode == "enforce", Source: func(policy.Event, string) (string, bool) { return i.Source, true }}
			before := calls.Load()
			d, err := e.Evaluate(policy.Event{Protocol: "network", ClientIP: i.Source, Body: "secret-body", Network: policy.NetworkEvent{SrcIP: i.Source, DstIP: "198.51.100.1", Transport: "tcp", SrcPort: 12345, DstPort: 443}})
			if err != nil || len(d.Effects) != 0 || calls.Load() != before {
				t.Fatalf("%s/%s emitted: %+v %v", mode, kind, d, err)
			}
		}
	}
	// Sink redirect is never followed and does not receive an automatic retry.
	var redirected atomic.Int32
	other := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected.Add(1) }))
	defer other.Close()
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, other.URL, 302) }))
	defer redirect.Close()
	root := x509.NewCertPool()
	root.AddCert(redirect.Certificate())
	cfg = configFor(t, redirect)
	cfg.TLSConfig = &tls.Config{RootCAs: root, MinVersion: tls.VersionTLS12}
	s = cfg.Scopes["edge"]
	s.Notification = true
	cfg.Scopes["edge"] = s
	rb := newBroker(t, cfg)
	i = typedIntent("notify", "")
	rb.Submit(i, i.Source)
	if r := await(t, rb, i.ID, "failed"); r.Reason != "notification-rejected" || redirected.Load() != 0 {
		t.Fatal(r)
	}
	// Expired notification admission performs no HTTP request.
	i = typedIntent("notify", "")
	i.IssuedAt = time.Now().Add(-time.Minute)
	i.ExpiresAt = i.IssuedAt.Add(i.TTL)
	i.ID = policy.IntentID(i)
	if r := b.Submit(i, i.Source); r.Status != "failed" {
		t.Fatal(r)
	}
}

func TestTypedBrokerRejectsLegacySchemaAndProtectedServices(t *testing.T) {
	c, _ := controller(t, true)
	var posts atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/leases" && r.Method == http.MethodPost {
			posts.Add(1)
			raw, _ := io.ReadAll(r.Body)
			var request map[string]json.RawMessage
			if json.Unmarshal(raw, &request) != nil {
				t.Error("invalid legacy request")
			}
			if _, exists := request["action"]; exists {
				t.Error("legacy block_source request gained unsupported action field")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			r.Body = io.NopCloser(strings.NewReader(string(raw)))
		}
		if r.URL.Path == "/mcp" {
			raw, _ := io.ReadAll(r.Body)
			if strings.Contains(string(raw), `"method":"tools/list"`) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"create_action_lease","inputSchema":{"properties":{"id":{"type":"string"}}}}]}}`)
				return
			}
			r.Body = io.NopCloser(strings.NewReader(string(raw)))
		}
		c.Handler().ServeHTTP(w, r)
	}))
	defer server.Close()
	cfg := configFor(t, server)
	b := newBroker(t, cfg)
	f := enforcer.Flow{Destination: "198.51.100.1", Protocol: "tcp", SourcePort: 12345, DestinationPort: 443}
	i := typedIntent("drop_flow", "")
	i.Target = "source"
	i.Flow = f
	i.ID = policy.IntentID(i)
	if r := b.SubmitFlow(i, i.Source, &f); r.Status != "requested" {
		t.Fatal(r)
	}
	if r := await(t, b, i.ID, "failed"); r.Reason != "action-schema-unavailable" || posts.Load() != 0 {
		t.Fatal(r)
	}
	// The legacy action still works without the new schema.
	i = typedIntent("block_source", "")
	b.Submit(i, i.Source)
	await(t, b, i.ID, "simulated")
	if posts.Load() != 1 {
		t.Fatal("legacy block_source compatibility failed")
	}
	s := cfg.Scopes["edge"]
	s.ProtectedServices = []enforcer.Service{{Protocol: "tcp", Port: 443}}
	cfg.Scopes["edge"] = s
	protected := newBroker(t, cfg)
	// Mutating the caller's grant cannot remove the protected service.
	s.ProtectedServices[0].Port = 22
	i = typedIntent("block_source", "")
	if r := protected.Submit(i, i.Source); r.Status != "failed" || posts.Load() != 1 {
		t.Fatal("protected service reached backend", r)
	}
}

func TestCapabilitiesFailClosedBeforeTypedMutation(t *testing.T) {
	c, _ := controller(t, true)
	for _, mutate := range []func(map[string]any){
		func(c map[string]any) { delete(c, "dry_run") },
		func(c map[string]any) { c["actions"] = []string{"block_source"} },
		func(c map[string]any) { c["absolute_deadlines"] = false },
		func(c map[string]any) { c["scope_mutable"] = true },
		func(c map[string]any) { c["generic_commands"] = true },
		func(c map[string]any) { c["max_ttl_seconds"] = 1 },
	} {
		var posts atomic.Int32
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/leases" && r.Method == http.MethodPost {
				posts.Add(1)
			}
			capture := httptest.NewRecorder()
			c.Handler().ServeHTTP(capture, r)
			if r.URL.Path == "/mcp" {
				var envelope map[string]any
				if err := json.Unmarshal(capture.Body.Bytes(), &envelope); err != nil {
					t.Error(err)
					w.WriteHeader(500)
					return
				}
				result, _ := envelope["result"].(map[string]any)
				content, _ := result["content"].([]any)
				if len(content) == 1 {
					entry := content[0].(map[string]any)
					var caps map[string]any
					if json.Unmarshal([]byte(entry["text"].(string)), &caps) != nil {
						t.Error("bad capabilities")
						w.WriteHeader(500)
						return
					}
					mutate(caps)
					raw, _ := json.Marshal(caps)
					entry["text"] = string(raw)
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(envelope)
					return
				}
			}
			for key, values := range capture.Header() {
				w.Header()[key] = values
			}
			w.WriteHeader(capture.Code)
			_, _ = w.Write(capture.Body.Bytes())
		}))
		b := newBroker(t, configFor(t, server))
		i := typedIntent("reject_flow", "")
		i.Target = "source"
		i.Flow = enforcer.Flow{Destination: "198.51.100.1", Protocol: "tcp", SourcePort: 12345, DestinationPort: 443}
		i.ID = policy.IntentID(i)
		if r := b.SubmitFlow(i, i.Source, &i.Flow); r.Status != "requested" {
			t.Fatal(r)
		}
		await(t, b, i.ID, "failed")
		if posts.Load() != 0 {
			t.Fatal("invalid capabilities allowed mutation")
		}
		_ = b.Close()
		server.Close()
	}
}
