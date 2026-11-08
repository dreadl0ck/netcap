package firewallauth_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/enforcer"
	"github.com/dreadl0ck/netcap/internal/firewallauth"
	"github.com/dreadl0ck/netcap/internal/firewallfleet"
	"github.com/dreadl0ck/netcap/internal/firewallui"
)

func TestConsoleIdentityOriginAndTypedApprovalComposition(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	actor := firewallauth.Principal{ID: "lease-actor", Grants: []firewallauth.Grant{{Scope: scope, Actions: []firewallauth.Action{firewallauth.Read, firewallauth.Lease}}}}
	approver := firewallauth.Principal{ID: "lease-approver", Grants: []firewallauth.Grant{{Scope: scope, Actions: []firewallauth.Action{firewallauth.Approve, firewallauth.Lease}}}}
	reader := firewallauth.Principal{ID: "lease-reader", Grants: []firewallauth.Grant{{Scope: scope, Actions: []firewallauth.Action{firewallauth.Read}}}}
	a, p, err := firewallauth.OpenPersistent(firewallauth.Config{Static: []firewallauth.Static{{Token: authorToken, Principal: actor}, {Token: readerToken, Principal: reader}}}, filepath.Join(t.TempDir(), "identity"), key, []firewallauth.Protected{{Scope: scope, Action: firewallauth.Lease}})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	c, err := enforcer.New(enforcer.Config{Auth: a, Approvals: p, AuthScope: scope, Origin: "http://example.com", DryRun: true, Scope: enforcer.Scope{Hook: "input", Interface: "eth0", DestinationCIDR: "10.1.0.0/24", Protocol: "tcp", Port: 443}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	h := firewallui.WrapOrigin(c.Handler(), "leases", "http://example.com", true)
	for _, origin := range []string{"http://example.com", "http://foreign.example.com", "null"} {
		w := request(h, "GET", "/v1/capabilities", readerToken, "", origin)
		want := 403
		if origin == "http://example.com" {
			want = 200
		}
		if w.Code != want {
			t.Fatalf("origin %s: %d %s", origin, w.Code, w.Body.String())
		}
	}
	if w := request(firewallui.WrapOrigin(c.Handler(), "leases", "http://different.example.com", true), "GET", "/v1/capabilities", readerToken, "", "http://example.com"); w.Code != 403 {
		t.Fatal("wrapper bypassed configured origin")
	}
	for _, path := range []string{"/console/", "/console/app.js", "/console/service"} {
		w := request(h, "GET", path, "", "", "")
		if strings.Contains(w.Body.String(), readerToken) || strings.Contains(w.Body.String(), authorToken) {
			t.Fatal("credential in unauthenticated asset")
		}
	}
	if w := request(h, "POST", "/v1/leases", readerToken, `{"id":"deny","source":"198.51.100.2","ttl_seconds":60}`, "http://example.com"); w.Code != 403 {
		t.Fatal("console reader mutated lease")
	}
	action := enforcer.Action{Kind: enforcer.RejectFlow, Flow: enforcer.Flow{Destination: "10.1.0.2", Protocol: "tcp", SourcePort: 23456, DestinationPort: 443}}
	expiry := time.Now().UTC().Add(time.Minute)
	receipt, err := p.Issue(firewallauth.WithPrincipal(context.Background(), approver), firewallauth.ApprovalRequest{Actor: actor.ID, Action: firewallauth.Lease, Scope: scope, Digest: enforcer.ActionApprovalDigest("typed", "198.51.100.2", 0, expiry, action)})
	if err != nil {
		t.Fatal(err)
	}
	ctx := firewallauth.WithReceipt(firewallauth.WithPrincipal(context.Background(), actor), receipt)
	modified := action
	modified.Kind = enforcer.DropFlow
	if _, err := c.CreateActionUntil(ctx, "typed", "198.51.100.2", expiry, modified); err == nil {
		t.Fatal("approval substituted action kind")
	}
	modified = action
	modified.Flow.SourcePort++
	if _, err := c.CreateActionUntil(ctx, "typed", "198.51.100.2", expiry, modified); err == nil {
		t.Fatal("approval substituted exact flow")
	}
	body, _ := json.Marshal(map[string]any{"id": "typed", "source": "198.51.100.2", "expires_at": expiry, "action": action, "receipt": receipt})
	if w := request(h, "POST", "/v1/leases", authorToken, string(body), "http://example.com"); w.Code != 201 {
		t.Fatalf("approved typed action: %d %s", w.Code, w.Body.String())
	}
	if w := request(h, "POST", "/v1/leases", authorToken, string(body), "http://example.com"); w.Code != 403 {
		t.Fatal("receipt replay")
	}
	if _, err := c.CreateActionUntil(context.Background(), "direct", "198.51.100.3", expiry, action); err == nil {
		t.Fatal("direct typed action bypassed authority")
	}
}

func TestFleetOperationsGrantsComposeAcrossTransports(t *testing.T) {
	operator := firewallauth.Principal{ID: "ops", Grants: []firewallauth.Grant{{Scope: scope, Actions: []firewallauth.Action{firewallauth.Prune, firewallauth.Audit}}, {Scope: firewallauth.Scope{Environment: scope.Environment}, Actions: []firewallauth.Action{firewallauth.Metrics}}}}
	a, err := firewallauth.New(firewallauth.Config{Static: []firewallauth.Static{{Token: readerToken, Principal: firewallauth.Principal{ID: "read", Grants: []firewallauth.Grant{{Scope: scope, Actions: []firewallauth.Action{firewallauth.Read}}}}}, {Token: authorToken, Principal: operator}}})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	s, err := firewallfleet.New(firewallfleet.Config{Auth: a, Environment: scope.Environment, StateDir: filepath.Join(t.TempDir(), "fleet")})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	resource := firewallfleet.Scope{Tenant: scope.Tenant, App: scope.App}
	for _, op := range []string{"audit_export", "audit_ack", "retention_preview", "prune"} {
		if _, err := s.Execute(context.Background(), readerToken, op, firewallfleet.Request{Scope: resource}); err == nil {
			t.Fatalf("reader direct %s", op)
		}
	}
	h := s.Handler()
	for _, op := range []string{"audit_export", "retention_preview"} {
		if !rpc(t, h, authorToken, "fleet_"+op, map[string]any{"scope": resource}) {
			t.Fatalf("ops MCP %s denied", op)
		}
		if rpc(t, h, readerToken, "fleet_"+op, map[string]any{"scope": resource}) {
			t.Fatalf("reader MCP %s granted", op)
		}
	}
	if !rpc(t, h, authorToken, "fleet_metrics", map[string]any{}) || rpc(t, h, readerToken, "fleet_metrics", map[string]any{}) {
		t.Fatal("MCP metrics grant")
	}
	for _, token := range []string{readerToken, authorToken} {
		want := 403
		if token == authorToken {
			want = 200
		}
		if w := request(h, "GET", "/metrics", token, "", ""); w.Code != want {
			t.Fatalf("REST metrics: %d %s", w.Code, w.Body.String())
		}
	}
	if w := request(h, "POST", "/api/v1/fleet/retention_preview", authorToken, `{"scope":{"tenant":"one","app":"web"}}`, ""); w.Code != 200 {
		t.Fatalf("REST preview: %d %s", w.Code, w.Body.String())
	}
	if w := request(h, "POST", "/api/v1/fleet/retention_preview", authorToken, `{"scope":{"tenant":"two","app":"web"}}`, ""); w.Code != 403 {
		t.Fatal("cross-tenant retention")
	}
}

func TestFleetRejectedStageAuditAcrossAuthoritiesAndTransports(t *testing.T) {
	for _, identity := range []bool{false, true} {
		for _, transport := range []string{"REST", "MCP"} {
			t.Run(fmt.Sprintf("identity=%t/%s", identity, transport), func(t *testing.T) {
				a, err := firewallauth.New(firewallauth.Config{Static: []firewallauth.Static{{Token: authorToken, Principal: firewallauth.Principal{ID: "author", Grants: []firewallauth.Grant{{Scope: scope, Actions: []firewallauth.Action{firewallauth.Author, firewallauth.Audit}}}}}}})
				if err != nil {
					t.Fatal(err)
				}
				defer a.Close()
				cfg := firewallfleet.Config{Token: authorToken, Environment: scope.Environment, StateDir: filepath.Join(t.TempDir(), "fleet"), AuditRequired: true}
				actor, grant := "administrator", "operator"
				if identity {
					cfg.Token, cfg.Auth = "", a
					actor, grant = "author", "author"
				}
				s, err := firewallfleet.New(cfg)
				if err != nil {
					t.Fatal(err)
				}
				defer s.Close()
				resource := firewallfleet.Scope{Tenant: scope.Tenant, App: scope.App}
				h := s.Handler()
				if transport == "REST" {
					w := request(h, "POST", "/api/v1/fleet/stage", authorToken, `{"scope":{"tenant":"one","app":"web"},"bundle":"{\"invalid\":true}"}`, "")
					if w.Code != 400 {
						t.Fatalf("stage: %d %s", w.Code, w.Body.String())
					}
				} else if rpc(t, h, authorToken, "fleet_stage", map[string]any{"scope": resource, "bundle": `{"invalid":true}`}) {
					t.Fatal("invalid stage accepted")
				}
				out, err := s.Execute(context.Background(), authorToken, "audit", firewallfleet.Request{Scope: resource})
				if err != nil {
					t.Fatal(err)
				}
				records := out.([]firewallfleet.Audit)
				if len(records) != 1 {
					t.Fatalf("audit: %+v", records)
				}
				r := records[0]
				if r.Actor != actor || r.Grant != grant || r.Outcome != "rejected" || r.Reason != "invalid" || r.Scope != resource {
					t.Fatalf("rejection: %+v", r)
				}
				for _, token := range []string{"invalid", authorToken} {
					foreign := firewallfleet.Scope{Tenant: "foreign", App: "web"}
					if identity || token == "invalid" {
						_, _ = s.Execute(context.Background(), token, "stage", firewallfleet.Request{Scope: foreign, Bundle: `{"invalid":true}`})
					}
				}
				out, err = s.Execute(context.Background(), authorToken, "audit", firewallfleet.Request{Scope: resource})
				if err != nil || len(out.([]firewallfleet.Audit)) != 1 {
					t.Fatalf("untrusted request altered audit: %v %v", out, err)
				}
			})
		}
	}
}
