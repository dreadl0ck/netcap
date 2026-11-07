package firewallauth_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/enforcer"
	"github.com/dreadl0ck/netcap/internal/firewallauth"
	"github.com/dreadl0ck/netcap/internal/firewallfleet"
	"github.com/dreadl0ck/netcap/internal/firewallstate"
	"github.com/dreadl0ck/netcap/internal/policy"
	"github.com/dreadl0ck/netcap/internal/policycontrol"
	"github.com/dreadl0ck/netcap/internal/policystate"
)

const readerToken = "read-only-identity-token-32-bytes"
const authorToken = "author-identity-token-32-bytes-long"
const foreignToken = "foreign-identity-token-32-bytes-long"

var scope = firewallauth.Scope{Tenant: "one", App: "web", Environment: "prod"}

func authority(t *testing.T) *firewallauth.Authority {
	t.Helper()
	other := scope
	other.Tenant = "two"
	a, err := firewallauth.New(firewallauth.Config{Static: []firewallauth.Static{
		{Token: readerToken, Principal: firewallauth.Principal{ID: "reader", Grants: []firewallauth.Grant{{Scope: scope, Actions: []firewallauth.Action{firewallauth.Read}}}}},
		{Token: authorToken, Principal: firewallauth.Principal{ID: "author", Grants: []firewallauth.Grant{{Scope: scope, Actions: []firewallauth.Action{firewallauth.Author, firewallauth.Evaluate}}}}},
		{Token: foreignToken, Principal: firewallauth.Principal{ID: "foreign", Grants: []firewallauth.Grant{{Scope: other, Actions: []firewallauth.Action{firewallauth.Read, firewallauth.Author, firewallauth.Deploy, firewallauth.Lease}}}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return a
}
func request(h http.Handler, method, path, token, body, origin string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func rpc(t *testing.T, h http.Handler, token, name string, args any) bool {
	t.Helper()
	for _, envelope := range []string{`{"jsonrpc":"2.0","id":10,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"auth-test","version":"1"}}}`, `{"jsonrpc":"2.0","id":11,"method":"tools/list"}`} {
		w := request(h, "POST", "/mcp", token, envelope, "")
		var response map[string]json.RawMessage
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &response) != nil || response["error"] != nil || response["result"] == nil {
			t.Fatalf("MCP handshake/list: %d %s", w.Code, w.Body.String())
		}
	}
	raw, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": name, "arguments": args}})
	w := request(h, "POST", "/mcp", token, string(raw), "")
	if w.Code != 200 {
		t.Fatalf("MCP transport %d: %s", w.Code, w.Body.String())
	}
	var result struct {
		Result struct {
			IsError bool  `json:"isError"`
			Content []any `json:"content"`
		} `json:"result"`
		Error any `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Error != nil || len(result.Result.Content) == 0 {
		t.Fatalf("RPC not dispatched: %s", w.Body.String())
	}
	return !result.Result.IsError
}

type target struct{ p *policy.Compiled }

func (t *target) Policy() *policy.Compiled     { return t.p }
func (t *target) SetPolicy(p *policy.Compiled) { t.p = p }

const bundle = `{"version":"1","id":"test","mode":"enforce","default":"allow","rules":[]}`

func TestPolicyRESTAndActualMCPGrantParity(t *testing.T) {
	b, err := policy.Parse([]byte(bundle))
	if err != nil {
		t.Fatal(err)
	}
	p, err := policy.Compile(b)
	if err != nil {
		t.Fatal(err)
	}
	s, err := policycontrol.New(policycontrol.Config{Auth: authority(t), Scope: scope, Origin: "https://console.example", Managed: true, StateDir: filepath.Join(t.TempDir(), "policy")}, &target{p})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	h := s.Handler()
	for _, tc := range []struct {
		token, op, tool, body string
		args                  any
		allowed               bool
	}{
		{readerToken, "revision", "get_policy_revision", "", map[string]any{}, true},
		{readerToken, "check", "check_policy_bundle", `{"bundle":` + quote(bundle) + `}`, map[string]any{"bundle": bundle}, false},
		{authorToken, "check", "check_policy_bundle", `{"bundle":` + quote(bundle) + `}`, map[string]any{"bundle": bundle}, true},
		{readerToken, "activate", "activate_policy_deployment", `{"revision":"x","expected_revision":"y","idempotency_key":"z"}`, map[string]any{"revision": "x", "expected_revision": "y", "idempotency_key": "z"}, false},
		{foreignToken, "revision", "get_policy_revision", "", map[string]any{}, false},
		{readerToken, "audit", "query_policy_audit", "", map[string]any{}, false},
	} {
		method := "POST"
		if tc.body == "" {
			method = "GET"
		}
		w := request(h, method, "/api/v1/policy/"+tc.op, tc.token, tc.body, "")
		if (w.Code == 200) != tc.allowed {
			t.Fatalf("REST %s %s: %d %s", tc.token, tc.op, w.Code, w.Body.String())
		}
		if got := rpc(t, h, tc.token, tc.tool, tc.args); got != tc.allowed {
			t.Fatalf("MCP %s grant mismatch", tc.tool)
		}
	}
	for origin, want := range map[string]int{"https://console.example": 200, "https://console.example.evil": 403, "null": 403} {
		w := request(h, "GET", "/api/v1/policy/revision", readerToken, "", origin)
		if w.Code != want {
			t.Fatalf("origin %s: %d", origin, w.Code)
		}
		if w.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Fatal("unexpected CORS")
		}
	}
	if w := request(h, "GET", "/api/v1/policy/revision", "bad", "", ""); w.Code != 401 {
		t.Fatal("invalid bearer not rejected")
	}
	if _, err = s.Execute(context.Background(), "revision", policycontrol.Request{}); err == nil {
		t.Fatal("direct unauthenticated execution")
	}
}
func quote(s string) string { b, _ := json.Marshal(s); return string(b) }

func TestFleetRESTMCPForeignScopeAndIndirectJobChecks(t *testing.T) {
	s, err := firewallfleet.New(firewallfleet.Config{Auth: authority(t), Environment: "prod", StateDir: filepath.Join(t.TempDir(), "fleet")})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	h := s.Handler()
	args := map[string]any{"scope": map[string]string{"tenant": "one", "app": "web"}}
	if w := request(h, "GET", "/api/v1/fleet/status?tenant=one&app=web", readerToken, "", ""); w.Code != 200 {
		t.Fatalf("read: %d %s", w.Code, w.Body.String())
	}
	if !rpc(t, h, readerToken, "fleet_status", args) {
		t.Fatal("authorized MCP read failed")
	}
	if w := request(h, "GET", "/api/v1/fleet/status?tenant=one&app=web", foreignToken, "", ""); w.Code != 403 {
		t.Fatalf("foreign REST: %d", w.Code)
	}
	if rpc(t, h, foreignToken, "fleet_status", args) {
		t.Fatal("foreign MCP read")
	}
	stage := map[string]any{"scope": args["scope"], "bundle": bundle}
	raw, _ := json.Marshal(stage)
	if w := request(h, "POST", "/api/v1/fleet/stage", readerToken, string(raw), ""); w.Code != 403 {
		t.Fatalf("reader mutation: %d", w.Code)
	}
	if rpc(t, h, readerToken, "fleet_stage", stage) {
		t.Fatal("reader MCP mutation")
	}
	if w := request(h, "POST", "/api/v1/fleet/stage", authorToken, string(raw), ""); w.Code != 200 {
		t.Fatalf("author stage: %d %s", w.Code, w.Body.String())
	}
	if !rpc(t, h, authorToken, "fleet_stage", stage) {
		t.Fatal("author MCP stage")
	}
	// A caller cannot use target arguments to narrow authorization while reading
	// the whole tenant, including via the non-HTTP operation entry point.
	limited, err := firewallauth.New(firewallauth.Config{Static: []firewallauth.Static{{Token: readerToken, Principal: firewallauth.Principal{ID: "limited", Grants: []firewallauth.Grant{{Scope: firewallauth.Scope{Tenant: "one", App: "web", Environment: "prod", Target: "edge"}, Actions: []firewallauth.Action{firewallauth.Read}}}}}}})
	if err != nil {
		t.Fatal(err)
	}
	s2, err := firewallfleet.New(firewallfleet.Config{Auth: limited, Environment: "prod", StateDir: filepath.Join(t.TempDir(), "fleet")})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if _, err = s2.Execute(context.Background(), readerToken, "status", firewallfleet.Request{Scope: firewallstate.Scope{Tenant: "one", App: "web"}, Targets: []string{"edge"}}); err == nil {
		t.Fatal("target-limited whole-scope read")
	}
}

func TestEnforcerAndStateUnderlyingRESTBoundaries(t *testing.T) {
	a := authority(t)
	e, err := enforcer.New(enforcer.Config{Auth: a, AuthScope: scope, DryRun: true, Scope: enforcer.Scope{Hook: "input", Interface: "veth0", DestinationCIDR: "10.44.0.1/32", Protocol: "tcp", Port: 443}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	reader, _ := a.Authenticate(context.Background(), readerToken)
	readerCtx := firewallauth.WithPrincipal(context.Background(), reader)
	if _, err = e.Create(context.Background(), "direct", "198.51.100.2", time.Minute); err == nil {
		t.Fatal("direct anonymous lease")
	}
	if _, err = e.CreateUntil(readerCtx, "direct", "198.51.100.2", time.Now().Add(time.Minute)); err == nil {
		t.Fatal("direct reader lease")
	}
	if e.Delete(readerCtx, "direct") == nil || e.Reconcile(readerCtx) == nil {
		t.Fatal("direct reader lease mutation")
	}
	if w := request(e.Handler(), "GET", "/v1/leases", readerToken, "", ""); w.Code != 200 {
		t.Fatalf("lease read %d", w.Code)
	}
	if w := request(e.Handler(), "POST", "/v1/leases", readerToken, `{"id":"test","source":"198.51.100.2","ttl_seconds":60}`, ""); w.Code != 403 {
		t.Fatalf("lease create %d", w.Code)
	}
	if rpc(t, e.Handler(), readerToken, "create_action_lease", map[string]any{"id": "test", "source": "198.51.100.2", "ttl_seconds": 60}) {
		t.Fatal("MCP lease bypass")
	}
	if w := request(e.Handler(), "DELETE", "/v1/leases/test", foreignToken, "", ""); w.Code != 403 {
		t.Fatalf("foreign lease delete %d", w.Code)
	}
	s, err := firewallstate.New(firewallstate.Config{Auth: a, Environment: "prod", StateDir: filepath.Join(t.TempDir(), "state")})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	bound := s.Bind(firewallstate.Scope{Tenant: "one", App: "web"})
	if s.Backup(readerCtx, filepath.Join(t.TempDir(), "forbidden.sqlite")) == nil {
		t.Fatal("reader backed up all state")
	}
	if _, err = bound.Count(readerCtx, firewallstate.Key{}, firewallstate.Window{}, time.Now()); err == nil {
		t.Fatal("direct reader counter")
	}
	if err = bound.(interface{ Probe(context.Context) error }).Probe(context.Background()); err == nil {
		t.Fatal("direct anonymous state probe")
	}
	if w := request(s.Handler(), "GET", "/api/v1/state/health", readerToken, "", ""); w.Code != 200 {
		t.Fatalf("state read %d %s", w.Code, w.Body.String())
	}
	if w := request(s.Handler(), "POST", "/api/v1/state/count", readerToken, `{}`, ""); w.Code != 403 {
		t.Fatalf("state mutation %d", w.Code)
	}
	n, err := policystate.New(policystate.Config{Auth: a, Environment: "prod", StateDir: filepath.Join(t.TempDir(), "native")})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	if n.Ready(context.Background()) == nil || n.ConsistentBackup(readerCtx, filepath.Join(t.TempDir(), "forbidden.sqlite")) == nil {
		t.Fatal("unauthorized native state API")
	}
	if _, err = n.Evaluate(readerCtx, firewallstate.Scope{Tenant: "one", App: "web"}, policystate.Request{}); err == nil {
		t.Fatal("direct reader native-state mutation")
	}
	if w := request(n.Handler(), "POST", policystate.EvaluatePath, readerToken, `{}`, ""); w.Code != 403 {
		t.Fatalf("native state mutation %d", w.Code)
	}
}

func compiled(t *testing.T, raw string) *policy.Compiled {
	t.Helper()
	b, err := policy.Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	p, err := policy.Compile(b)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestProtectedPolicyActivationReceiptAndOrdinaryAuthoring(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	actor := firewallauth.Principal{ID: "agent", Grants: []firewallauth.Grant{{Scope: scope, Actions: []firewallauth.Action{firewallauth.Read, firewallauth.Author, firewallauth.Deploy}}}}
	operator := firewallauth.Principal{ID: "operator", Grants: []firewallauth.Grant{{Scope: scope, Actions: []firewallauth.Action{firewallauth.Approve, firewallauth.Deploy}}}}
	a, approvals, err := firewallauth.OpenPersistent(firewallauth.Config{Static: []firewallauth.Static{{Token: authorToken, Principal: actor}, {Token: foreignToken, Principal: operator}}}, filepath.Join(t.TempDir(), "identity"), key, []firewallauth.Protected{{Action: firewallauth.Deploy, Scope: scope}})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	p := compiled(t, bundle)
	target := &target{p: p}
	s, err := policycontrol.New(policycontrol.Config{Auth: a, Approvals: approvals, Scope: scope, Managed: true, StateDir: filepath.Join(t.TempDir(), "policy")}, target)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	changed := strings.Replace(bundle, `"id":"test"`, `"id":"next"`, 1)
	next := compiled(t, changed)
	if !rpc(t, s.Handler(), authorToken, "stage_policy_revision", map[string]any{"bundle": changed, "idempotency_key": "stage"}) {
		t.Fatal("ordinary authoring demanded approval")
	}
	r := policycontrol.Request{Revision: next.Revision(), ExpectedRevision: p.Revision(), IdempotencyKey: "activate"}
	args := map[string]any{"revision": r.Revision, "expected_revision": r.ExpectedRevision, "idempotency_key": r.IdempotencyKey}
	if rpc(t, s.Handler(), authorToken, "activate_policy_deployment", args) {
		t.Fatal("unapproved activation")
	}
	approval := firewallauth.ApprovalRequest{Actor: actor.ID, Action: firewallauth.Deploy, Scope: scope, Digest: policycontrol.ApprovalDigest("activate", r)}
	raw, _ := json.Marshal(map[string]any{"approval": approval})
	if w := request(s.Handler(), "POST", "/api/v1/policy/approval", authorToken, string(raw), ""); w.Code != 403 {
		t.Fatalf("self approval %d", w.Code)
	}
	w := request(s.Handler(), "POST", "/api/v1/policy/approval", foreignToken, string(raw), "")
	if w.Code != 200 {
		t.Fatalf("approval %d %s", w.Code, w.Body.String())
	}
	var receipt map[string]string
	if err = json.Unmarshal(w.Body.Bytes(), &receipt); err != nil {
		t.Fatal(err)
	}
	args["receipt"] = receipt["receipt"]
	args["expected_revision"] = "stale"
	if rpc(t, s.Handler(), authorToken, "activate_policy_deployment", args) {
		t.Fatal("changed CAS accepted")
	}
	args["expected_revision"] = r.ExpectedRevision
	args["approved"] = true
	if rpc(t, s.Handler(), authorToken, "activate_policy_deployment", args) {
		t.Fatal("agent approval field accepted")
	}
	delete(args, "approved")
	if !rpc(t, s.Handler(), authorToken, "activate_policy_deployment", args) {
		t.Fatal("approved activation failed")
	}
	if target.Policy().Revision() != next.Revision() {
		t.Fatal("policy not deployed")
	}
	if rpc(t, s.Handler(), authorToken, "activate_policy_deployment", args) {
		t.Fatal("receipt replay accepted")
	}
	r.IdempotencyKey = "stale-cas"
	approval.Digest = policycontrol.ApprovalDigest("activate", r)
	newReceipt, err := approvals.Issue(firewallauth.WithPrincipal(context.Background(), operator), approval)
	if err != nil {
		t.Fatal(err)
	}
	r.Receipt = newReceipt
	raw, _ = json.Marshal(r)
	if w := request(s.Handler(), "POST", "/api/v1/policy/activate", authorToken, string(raw), ""); w.Code != 409 {
		t.Fatalf("valid receipt bypassed stale CAS: %d %s", w.Code, w.Body.String())
	}
}

func TestFleetJobTargetsAndWorkloadCredentials(t *testing.T) {
	ctx := context.Background()
	all := scope
	all.Target = "*"
	edge := scope
	edge.Target = "edge"
	limited := scope
	limited.Target = "other"
	a, err := firewallauth.New(firewallauth.Config{Static: []firewallauth.Static{
		{Token: authorToken, Principal: firewallauth.Principal{ID: "admin", Grants: []firewallauth.Grant{{Scope: all, Actions: []firewallauth.Action{firewallauth.Read, firewallauth.Author, firewallauth.Deploy}}}}},
		{Token: readerToken, Principal: firewallauth.Principal{ID: "limited", Grants: []firewallauth.Grant{{Scope: limited, Actions: []firewallauth.Action{firewallauth.Read, firewallauth.Deploy}}}}},
		{Token: foreignToken, Principal: firewallauth.Principal{ID: "edge", Grants: []firewallauth.Grant{{Scope: edge, Actions: []firewallauth.Action{firewallauth.Lease}}}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	fs := firewallstate.Scope{Tenant: "one", App: "web"}
	s, err := firewallfleet.New(firewallfleet.Config{Auth: a, Environment: "prod", StateDir: filepath.Join(t.TempDir(), "fleet"), Targets: []firewallfleet.Enrollment{{ID: "edge", Scope: fs}}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	p := compiled(t, bundle)
	if _, err = s.Execute(ctx, authorToken, "stage", firewallfleet.Request{Scope: fs, Bundle: bundle}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Execute(ctx, authorToken, "rollout", firewallfleet.Request{Scope: fs, ID: "job", Revision: p.Revision(), Targets: []string{"edge"}, Expected: map[string]int64{"edge": 0}, Deadline: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	r := firewallfleet.Request{Scope: fs, ID: "job", ExpectedPhase: "staged", Targets: []string{"other"}}
	if _, err = s.Execute(ctx, readerToken, "activate", r); err == nil {
		t.Fatal("job target grant bypass")
	}
	if rpc(t, s.Handler(), readerToken, "fleet_activate", map[string]any{"scope": fs, "id": "job", "expected_phase": "staged"}) {
		t.Fatal("MCP indirect job grant bypass")
	}
	r.Targets = nil
	if _, err = s.Execute(ctx, authorToken, "activate", r); err != nil {
		t.Fatal(err)
	}
	d, err := s.Desired(ctx, foreignToken)
	if err != nil {
		t.Fatal("authority workload rejected", err)
	}
	if d.TargetID != "edge" || d.Generation != 1 {
		t.Fatalf("desired %+v", d)
	}
	if err = s.Acknowledge(ctx, foreignToken, firewallfleet.Ack{Generation: d.Generation, Revision: d.Revision}); err != nil {
		t.Fatal("authority ack rejected", err)
	}
	if _, err = s.Desired(ctx, authorToken); err == nil {
		t.Fatal("admin implicitly became workload")
	}
	if _, err = s.Maintain(ctx); err == nil {
		t.Fatal("ambient fleet maintenance")
	}
}

type leaseBackend struct {
	leases                  map[string]enforcer.Lease
	reads, applies, deletes int
}

func (b *leaseBackend) List(context.Context) ([]enforcer.Lease, error) {
	b.reads++
	out := []enforcer.Lease{}
	for _, l := range b.leases {
		out = append(out, l)
	}
	return out, nil
}
func (b *leaseBackend) Apply(_ context.Context, l enforcer.Lease) error {
	b.applies++
	b.leases[l.ID] = l
	return nil
}
func (b *leaseBackend) Delete(_ context.Context, l enforcer.Lease) error {
	b.deletes++
	delete(b.leases, l.ID)
	return nil
}

func TestEnforcerProtectedReceiptsAndReadsHaveNoBackendEffects(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	actor := firewallauth.Principal{ID: "agent", Grants: []firewallauth.Grant{{Scope: scope, Actions: []firewallauth.Action{firewallauth.Read, firewallauth.Lease}}}}
	op := firewallauth.Principal{ID: "operator", Grants: []firewallauth.Grant{{Scope: scope, Actions: []firewallauth.Action{firewallauth.Lease, firewallauth.Approve}}}}
	a, approvals, err := firewallauth.OpenPersistent(firewallauth.Config{Static: []firewallauth.Static{{Token: authorToken, Principal: actor}, {Token: foreignToken, Principal: op}}}, filepath.Join(t.TempDir(), "identity"), key, []firewallauth.Protected{{Action: firewallauth.Lease, Scope: scope}})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b := &leaseBackend{leases: map[string]enforcer.Lease{}}
	e, err := enforcer.New(enforcer.Config{Auth: a, Approvals: approvals, AuthScope: scope, Scope: enforcer.Scope{Hook: "input", Interface: "veth0", DestinationCIDR: "10.44.0.1/32", Protocol: "tcp", Port: 443}}, b)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	reads := b.reads
	if !rpc(t, e.Handler(), authorToken, "list_action_leases", map[string]any{}) {
		t.Fatal("lease read failed")
	}
	if b.reads != reads || b.applies != 0 || b.deletes != 0 {
		t.Fatal("read caused backend reconciliation")
	}
	args := map[string]any{"id": "lease", "source": "198.51.100.2", "ttl_seconds": 60}
	if rpc(t, e.Handler(), authorToken, "create_action_lease", args) {
		t.Fatal("unapproved MCP lease")
	}
	raw, _ := json.Marshal(args)
	if w := request(e.Handler(), "POST", "/v1/leases", authorToken, string(raw), ""); w.Code != 403 {
		t.Fatalf("unapproved REST lease %d", w.Code)
	}
	approval := firewallauth.ApprovalRequest{Actor: actor.ID, Action: firewallauth.Lease, Scope: scope, Digest: enforcer.CreateApprovalDigest("lease", "198.51.100.2", time.Minute, time.Time{})}
	raw, _ = json.Marshal(approval)
	w := request(e.Handler(), "POST", "/v1/approval", foreignToken, string(raw), "")
	if w.Code != 200 {
		t.Fatalf("issue lease approval %d %s", w.Code, w.Body.String())
	}
	var receipt map[string]string
	if err = json.Unmarshal(w.Body.Bytes(), &receipt); err != nil {
		t.Fatal(err)
	}
	args["receipt"] = receipt["receipt"]
	if !rpc(t, e.Handler(), authorToken, "create_action_lease", args) {
		t.Fatal("approved MCP lease failed")
	}
	if rpc(t, e.Handler(), authorToken, "create_action_lease", args) {
		t.Fatal("replayed lease receipt")
	}
	if b.applies != 1 || b.deletes != 0 {
		t.Fatalf("backend effects: %+v", b)
	}
	// Revocation approval binds the current lease deadline, so a receipt for an
	// earlier lease with the same ID cannot flush its replacement.
	lease := b.leases["lease"]
	deletion := firewallauth.ApprovalRequest{Actor: actor.ID, Action: firewallauth.Lease, Scope: scope, Digest: enforcer.DeleteApprovalDigest(lease)}
	stale := lease
	stale.ExpiresAt = stale.ExpiresAt.Add(-time.Second)
	staleRequest := deletion
	staleRequest.Digest = enforcer.DeleteApprovalDigest(stale)
	staleReceipt, err := approvals.Issue(firewallauth.WithPrincipal(context.Background(), op), staleRequest)
	if err != nil {
		t.Fatal(err)
	}
	if err = e.Delete(firewallauth.WithReceipt(firewallauth.WithPrincipal(context.Background(), actor), staleReceipt), "lease"); err == nil {
		t.Fatal("stale lease generation receipt accepted")
	}
	receiptToken, err := approvals.Issue(firewallauth.WithPrincipal(context.Background(), op), deletion)
	if err != nil {
		t.Fatal(err)
	}
	ctx := firewallauth.WithReceipt(firewallauth.WithPrincipal(context.Background(), actor), receiptToken)
	if err = e.Delete(ctx, "lease"); err != nil {
		t.Fatal(err)
	}
	if b.deletes != 1 {
		t.Fatal("approved revoke did not delete exact lease")
	}
}

func TestSharedCountersAreTenantBoundThroughRESTAndDirectCalls(t *testing.T) {
	one, two := scope, scope
	two.Tenant = "two"
	a, err := firewallauth.New(firewallauth.Config{Static: []firewallauth.Static{
		{Token: authorToken, Principal: firewallauth.Principal{ID: "one", Grants: []firewallauth.Grant{{Scope: one, Actions: []firewallauth.Action{firewallauth.Evaluate}}}}},
		{Token: foreignToken, Principal: firewallauth.Principal{ID: "two", Grants: []firewallauth.Grant{{Scope: two, Actions: []firewallauth.Action{firewallauth.Evaluate}}}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	s, err := firewallstate.New(firewallstate.Config{Auth: a, Environment: "prod", StateDir: filepath.Join(t.TempDir(), "state")})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	k := firewallstate.Key{Revision: strings.Repeat("a", 64), Group: strings.Repeat("b", 64)}
	window := firewallstate.Window{Mode: "fixed", Duration: time.Hour}
	raw, _ := json.Marshal(firewallstate.CountRequest{Key: k, Window: window})
	for _, token := range []string{authorToken, foreignToken} {
		w := request(s.Handler(), "POST", "/api/v1/state/count", token, string(raw), "")
		if w.Code != 200 {
			t.Fatalf("count %d %s", w.Code, w.Body.String())
		}
		var out firewallstate.CountResult
		if err = json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		if out.Count != 1 {
			t.Fatal("cross-tenant counter", out)
		}
	}
	p, _ := a.Authenticate(context.Background(), authorToken)
	if _, err = s.Bind(firewallstate.Scope{Tenant: "two", App: "web"}).Count(firewallauth.WithPrincipal(context.Background(), p), k, window, time.Now()); err == nil {
		t.Fatal("direct foreign tenant binding")
	}
}

func TestIndependentReplicaLedgersFailClosedBeforeConnecting(t *testing.T) {
	a := authority(t)
	const noConnection = "postgres://not-contacted.invalid/database"
	if _, err := firewallfleet.New(firewallfleet.Config{Auth: a, DatabaseURL: noConnection}); err == nil || !strings.Contains(err.Error(), "shared identity ledger") {
		t.Fatal("fleet replica ledger gate", err)
	}
	if _, err := firewallstate.New(firewallstate.Config{Auth: a, DatabaseURL: noConnection}); err == nil || !strings.Contains(err.Error(), "shared identity ledger") {
		t.Fatal("sharedstate replica ledger gate", err)
	}
	if _, err := policystate.New(policystate.Config{Auth: a, DatabaseURL: noConnection}); err == nil || !strings.Contains(err.Error(), "shared identity ledger") {
		t.Fatal("policystate replica ledger gate", err)
	}
}

func TestRetainedPolicyStateCannotChangeTenantOrDowngradeIdentity(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "policy")
	a := authority(t)
	cfg := policycontrol.Config{Auth: a, Scope: scope, Managed: true, StateDir: dir}
	s, err := policycontrol.New(cfg, &target{p: compiled(t, bundle)})
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	foreign := cfg
	foreign.Scope.Tenant = "two"
	if svc, err := policycontrol.New(foreign, &target{p: compiled(t, bundle)}); err == nil {
		svc.Close()
		t.Fatal("retained policy rebound to foreign tenant")
	}
	legacy := cfg
	legacy.Auth = nil
	legacy.Token = readerToken
	if svc, err := policycontrol.New(legacy, &target{p: compiled(t, bundle)}); err == nil {
		svc.Close()
		t.Fatal("retained shared identity state downgraded to legacy")
	}
	s, err = policycontrol.New(cfg, &target{p: compiled(t, bundle)})
	if err != nil {
		t.Fatal("same identity scope restart", err)
	}
	s.Close()
}

func TestNativeEvaluationWithAuthorityAndTenantIsolationAfterRestart(t *testing.T) {
	one, two := scope, scope
	two.Tenant = "two"
	a, err := firewallauth.New(firewallauth.Config{Static: []firewallauth.Static{
		{Token: authorToken, Principal: firewallauth.Principal{ID: "one", Grants: []firewallauth.Grant{{Scope: one, Actions: []firewallauth.Action{firewallauth.Read, firewallauth.Evaluate}}}}},
		{Token: foreignToken, Principal: firewallauth.Principal{ID: "two", Grants: []firewallauth.Grant{{Scope: two, Actions: []firewallauth.Action{firewallauth.Read, firewallauth.Evaluate}}}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	p, err := policy.Compile(policy.Bundle{Version: "1", ID: "isolation", Mode: "enforce", Default: "allow", Rules: []policy.Rule{{ID: "rate", Action: "deny", Expression: "true", Threshold: &policy.Threshold{Count: 2, Window: "1h", Mode: "fixed", GroupBy: "ClientIP"}}}})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(p.Bundle())
	raw, _ := json.Marshal(policystate.Request{Revision: p.Revision(), Bundle: b, Event: &policy.Event{ClientIP: "192.0.2.1"}})
	cfg := policystate.Config{Auth: a, Environment: "prod", StateDir: filepath.Join(t.TempDir(), "native")}
	s, err := policystate.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	check := func(token, verdict string) {
		t.Helper()
		w := request(s.Handler(), "POST", policystate.EvaluatePath, token, string(raw), "")
		if w.Code != 200 {
			t.Fatalf("native evaluation %d %s", w.Code, w.Body.String())
		}
		var d policy.Decision
		if err := json.Unmarshal(w.Body.Bytes(), &d); err != nil || d.Verdict != verdict {
			t.Fatalf("native verdict %+v %v", d, err)
		}
	}
	check(authorToken, "allow")
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = policystate.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	check(foreignToken, "allow")
	check(authorToken, "deny")
}
