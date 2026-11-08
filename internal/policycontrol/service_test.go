package policycontrol

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/dreadl0ck/netcap/internal/policy"
)

type testTarget struct {
	current atomic.Pointer[policy.Compiled]
	writes  atomic.Int32
}

func (t *testTarget) Policy() *policy.Compiled     { return t.current.Load() }
func (t *testTarget) SetPolicy(c *policy.Compiled) { t.writes.Add(1); t.current.Store(c) }

func bundle(id string) string {
	return fmt.Sprintf(`{"version":"1","id":%q,"mode":"enforce","default":"allow","rules":[{"id":"private","expression":"Path == '/private'","action":"deny"}]}`, id)
}
func target(t *testing.T) *testTarget {
	t.Helper()
	c, _, err := compile([]byte(bundle("bootstrap")))
	if err != nil {
		t.Fatal(err)
	}
	result := new(testTarget)
	result.current.Store(c)
	return result
}
func service(t *testing.T, managed bool) (*Service, *testTarget) {
	t.Helper()
	dst := target(t)
	s, err := New(Config{Token: "test-secret", Managed: managed, StateDir: filepath.Join(t.TempDir(), "state")}, dst)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, dst
}
func exec(t *testing.T, s *Service, op string, r Request) json.RawMessage {
	t.Helper()
	result, err := s.Execute(context.Background(), op, r)
	if err != nil {
		t.Fatalf("%s: %v", op, err)
	}
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func stage(t *testing.T, s *Service, id string) string {
	t.Helper()
	var result struct {
		Revision string `json:"revision"`
	}
	if err := json.Unmarshal(exec(t, s, "stage", Request{Bundle: bundle(id), IdempotencyKey: "stage-" + id}), &result); err != nil {
		t.Fatal(err)
	}
	return result.Revision
}
func wantStatus(t *testing.T, err error, status int) {
	t.Helper()
	if err == nil {
		t.Fatalf("wanted status %d, got success", status)
	}
	code, _ := publicError(err)
	if code != status {
		t.Fatalf("wanted status %d, got %d: %v", status, code, err)
	}
}

func TestDefaultsAndReadOnly(t *testing.T) {
	dst := target(t)
	if _, err := New(Config{}, dst); err == nil {
		t.Fatal("empty token accepted")
	}
	if _, err := New(Config{Token: "secret", Managed: true}, dst); err == nil {
		t.Fatal("managed without StateDir accepted")
	}
	for _, cfg := range []Config{{Token: "secret"}, {Token: "secret", Managed: true, ReadOnly: true}} {
		s, err := New(cfg, dst)
		if err != nil {
			t.Fatal(err)
		}
		for _, op := range []string{"stage", "activate", "rollback"} {
			_, err = s.Execute(context.Background(), op, Request{})
			wantStatus(t, err, 403)
		}
		if !bytes.Contains(exec(t, s, "capabilities", Request{}), []byte(`"read_only":true`)) {
			t.Fatal("incorrect mode")
		}
		_ = s.Close()
	}
	if dst.writes.Load() != 0 {
		t.Fatal("file mode mutated target")
	}
}

func TestImmutableStageCASIdempotencyAndRollback(t *testing.T) {
	s, dst := service(t, true)
	initial := dst.Policy().Revision()
	rev := stage(t, s, "second")
	if dst.writes.Load() != 0 || dst.Policy().Revision() != initial {
		t.Fatal("stage changed target")
	}
	r := Request{Revision: rev, ExpectedRevision: initial, IdempotencyKey: "activate-second"}
	first := exec(t, s, "activate", r)
	if dst.Policy().Revision() != rev || dst.writes.Load() != 1 {
		t.Fatal("activation failed")
	}
	if !bytes.Equal(first, exec(t, s, "activate", r)) || dst.writes.Load() != 1 {
		t.Fatal("idempotent retry mutated target")
	}
	exec(t, s, "activate", Request{Revision: rev, ExpectedRevision: rev, IdempotencyKey: "already-active"})
	if dst.writes.Load() != 1 {
		t.Fatal("same-revision activation reset live evaluator")
	}
	r.Revision = initial
	_, err := s.Execute(context.Background(), "activate", r)
	wantStatus(t, err, 409)
	r.IdempotencyKey = "stale-cas"
	_, err = s.Execute(context.Background(), "activate", r)
	wantStatus(t, err, 409)
	exec(t, s, "rollback", Request{ExpectedRevision: rev, IdempotencyKey: "rollback"})
	if dst.Policy().Revision() != initial || dst.writes.Load() != 2 {
		t.Fatal("rollback failed")
	}
	var audit []Audit
	if err = json.Unmarshal(exec(t, s, "audit", Request{}), &audit); err != nil {
		t.Fatal(err)
	}
	if len(audit) != 4 || audit[0].Operation != "rollback" {
		t.Fatalf("audit: %+v", audit)
	}
	if !bytes.Contains(exec(t, s, "diff", Request{Revision: initial, OtherRevision: rev}), []byte(`"id"`)) {
		t.Fatal("diff missing changed bundle ID")
	}
	_, err = s.Execute(context.Background(), "stage", Request{Bundle: `{"version":"wrong"}`, IdempotencyKey: "invalid"})
	wantStatus(t, err, 400)
	if dst.writes.Load() != 2 {
		t.Fatal("invalid bundle changed target")
	}
}

func TestConcurrentCAS(t *testing.T) {
	s, dst := service(t, true)
	initial := dst.Policy().Revision()
	a := stage(t, s, "a")
	b := stage(t, s, "b")
	var wg sync.WaitGroup
	var successes atomic.Int32
	errs := make(chan error, 2)
	for i, rev := range []string{a, b} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.Execute(context.Background(), "activate", Request{Revision: rev, ExpectedRevision: initial, IdempotencyKey: fmt.Sprint("activate-", i)})
			if err == nil {
				successes.Add(1)
			} else {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	if successes.Load() != 1 || dst.writes.Load() != 1 {
		t.Fatalf("successes=%d writes=%d", successes.Load(), dst.writes.Load())
	}
	for err := range errs {
		wantStatus(t, err, 409)
	}
}

func TestRestartSingletonAndCorruptState(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	cfg := Config{Token: "secret", Managed: true, StateDir: dir}
	dst := target(t)
	s, err := New(cfg, dst)
	if err != nil {
		t.Fatal(err)
	}
	rev := stage(t, s, "durable")
	initial := dst.Policy().Revision()
	r := Request{Revision: rev, ExpectedRevision: initial, IdempotencyKey: "durable-activate"}
	response := exec(t, s, "activate", r)
	if other, err := New(cfg, target(t)); err == nil {
		_ = other.Close()
		t.Fatal("second owner accepted")
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	dst = target(t)
	s, err = New(cfg, dst)
	if err != nil {
		t.Fatal(err)
	}
	if dst.Policy().Revision() != rev {
		t.Fatal("restart lost active revision")
	}
	if !bytes.Equal(response, exec(t, s, "activate", r)) || dst.writes.Load() != 1 {
		t.Fatal("restart lost idempotency receipt")
	}
	if len(exec(t, s, "audit", Request{})) < 10 {
		t.Fatal("restart lost audit")
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(dir, "policycontrol.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE revisions SET bundle='invalid' WHERE revision=?`, initial); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	dst = target(t)
	if s, err = New(cfg, dst); err == nil {
		_ = s.Close()
		t.Fatal("invalid inactive persisted bundle accepted")
	}
	if dst.writes.Load() != 0 {
		t.Fatal("failed startup mutated target")
	}
	// File mode never reads managed state, even if it is invalid.
	cfg.Managed = false
	s, err = New(cfg, dst)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
}

func TestReplayDoesNotTouchLiveThresholds(t *testing.T) {
	s, dst := service(t, false)
	b := dst.Policy().Bundle()
	b.Rules[0].Threshold = &policy.Threshold{Count: 2, Window: "1h", GroupBy: "ClientIP"}
	c, err := policy.Compile(b)
	if err != nil {
		t.Fatal(err)
	}
	dst.current.Store(c)
	event := policy.Event{Method: "GET", Path: "/private", ClientIP: "192.0.2.1", Phase: "request"}
	for range 4 {
		var decision policy.Decision
		if err = json.Unmarshal(exec(t, s, "evaluate", Request{Event: event}), &decision); err != nil {
			t.Fatal(err)
		}
		if decision.Verdict != "allow" {
			t.Fatal("replay retained synthetic counters")
		}
	}
	decision, err := dst.Policy().Evaluate(event)
	if err != nil || decision.Verdict != "allow" {
		t.Fatalf("replay changed live counter: %+v %v", decision, err)
	}
	decision, err = dst.Policy().Evaluate(event)
	if err != nil || decision.Verdict != "deny" {
		t.Fatalf("live threshold not working: %+v %v", decision, err)
	}
	if dst.writes.Load() != 0 {
		t.Fatal("replay invoked SetPolicy")
	}
}

func TestRESTAuthLimitsAndReadOnly(t *testing.T) {
	s, dst := service(t, false)
	handler := s.Handler()
	for _, path := range []string{"/api/v1/policy/capabilities", "/api/v1/policy/activate", "/mcp"} {
		for _, token := range []string{"", "Bearer wrong", "test-secret"} {
			r := httptest.NewRequest("POST", path, strings.NewReader(`{}`))
			r.Header.Set("Authorization", token)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != 401 {
				t.Fatalf("%s unauthorized=%d", path, w.Code)
			}
		}
	}
	for _, tc := range []struct {
		method, path, body string
		status             int
	}{
		{"GET", "/api/v1/policy/capabilities", "", 200},
		{"POST", "/api/v1/policy/activate", `{}`, 403},
		{"POST", "/api/v1/policy/stage", `{}`, 403},
		{"POST", "/api/v1/policy/check", `{"bundle":"invalid"}`, 400},
		{"POST", "/api/v1/policy/check", `{"bundle":"x","path":"/etc/passwd"}`, 400},
		{"POST", "/api/v1/policy/check", `{} {}`, 400},
		{"GET", "/api/v1/policy/audit?limit=2049", "", 400},
		{"POST", "/api/v1/policy/check", strings.Repeat(" ", MaxInputBytes+1), 413},
	} {
		r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		r.Header.Set("Authorization", "Bearer test-secret")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatalf("%s got %d: %s", tc.path, w.Code, w.Body.String())
		}
	}
	if dst.writes.Load() != 0 {
		t.Fatal("REST read-only request mutated target")
	}
}

func TestRESTManagedDeployment(t *testing.T) {
	s, dst := service(t, true)
	h := s.Handler()
	initial := dst.Policy().Revision()
	post := func(path string, r Request, key string, status int) []byte {
		t.Helper()
		data, _ := json.Marshal(r)
		req := httptest.NewRequest("POST", "/api/v1/policy/"+path, bytes.NewReader(data))
		req.Header.Set("Authorization", "Bearer test-secret")
		req.Header.Set("Idempotency-Key", key)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != status {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
		return w.Body.Bytes()
	}
	var staged struct {
		Revision string `json:"revision"`
	}
	if err := json.Unmarshal(post("revisions", Request{Bundle: bundle("rest")}, "rest-stage", 200), &staged); err != nil {
		t.Fatal(err)
	}
	request := Request{Revision: staged.Revision, ExpectedRevision: initial}
	first := post("activate", request, "rest-activate", 200)
	if !bytes.Equal(first, post("activate", request, "rest-activate", 200)) || dst.writes.Load() != 1 {
		t.Fatal("REST idempotency failed")
	}
	post("activate", request, "rest-stale", 409)
	post("rollback", Request{ExpectedRevision: staged.Revision}, "rest-rollback", 200)
	if dst.Policy().Revision() != initial {
		t.Fatal("REST rollback failed")
	}
}

func rpc(t *testing.T, client *http.Client, url, method string, params any) map[string]json.RawMessage {
	t.Helper()
	raw, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	req, err := http.NewRequest("POST", url+"/mcp", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer test-secret")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("RPC %s HTTP %d: %s", method, resp.StatusCode, data)
	}
	var envelope map[string]json.RawMessage
	if err = json.Unmarshal(data, &envelope); err != nil {
		t.Fatalf("RPC response: %s: %v", data, err)
	}
	if len(envelope["error"]) != 0 {
		t.Fatalf("RPC %s error: %s", method, data)
	}
	return envelope
}
func tool(t *testing.T, client *http.Client, url, name string, args any, wantError bool) json.RawMessage {
	t.Helper()
	env := rpc(t, client, url, "tools/call", map[string]any{"name": name, "arguments": args})
	var result struct {
		IsError bool `json:"isError"`
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(env["result"], &result); err != nil {
		t.Fatal(err)
	}
	if result.IsError != wantError || len(result.Content) != 1 {
		t.Fatalf("%s result=%s", name, env["result"])
	}
	return json.RawMessage(result.Content[0].Text)
}

func TestActualMCPProtocol(t *testing.T) {
	s, dst := service(t, true)
	web := httptest.NewServer(s.Handler())
	defer web.Close()
	client := web.Client()
	init := rpc(t, client, web.URL, "initialize", map[string]any{"protocolVersion": "2025-03-26", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "policycontrol-test", "version": "1"}})
	if !bytes.Contains(init["result"], []byte("netcap-policycontrol")) {
		t.Fatalf("initialize: %s", init["result"])
	}
	req, _ := http.NewRequest("POST", web.URL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
	req.Header.Set("Authorization", "Bearer test-secret")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 202 {
		t.Fatalf("initialized notification: %d", resp.StatusCode)
	}
	list := rpc(t, client, web.URL, "tools/list", map[string]any{})
	var tools struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(list["result"], &tools); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"get_policy_capabilities": true, "get_policy_revision": true, "check_policy_bundle": true, "stage_policy_revision": true, "diff_policy_revisions": true, "explain_policy_decision": true, "activate_policy_deployment": true, "rollback_policy_deployment": true, "query_policy_audit": true}
	for _, entry := range tools.Tools {
		if !want[entry.Name] {
			t.Fatalf("unexpected tool %s", entry.Name)
		}
		delete(want, entry.Name)
	}
	if len(want) != 0 {
		t.Fatalf("missing tools %v", want)
	}
	initial := dst.Policy().Revision()
	tool(t, client, web.URL, "get_policy_capabilities", map[string]any{}, false)
	tool(t, client, web.URL, "get_policy_revision", map[string]any{}, false)
	tool(t, client, web.URL, "check_policy_bundle", map[string]any{"bundle": bundle("mcp")}, false)
	tool(t, client, web.URL, "check_policy_bundle", map[string]any{"bundle": "invalid"}, true)
	var staged struct {
		Revision string `json:"revision"`
	}
	if err := json.Unmarshal(tool(t, client, web.URL, "stage_policy_revision", map[string]any{"bundle": bundle("mcp"), "idempotency_key": "mcp-stage"}, false), &staged); err != nil {
		t.Fatal(err)
	}
	tool(t, client, web.URL, "diff_policy_revisions", map[string]any{"revision": initial, "other_revision": staged.Revision}, false)
	decision := tool(t, client, web.URL, "explain_policy_decision", map[string]any{"revision": staged.Revision, "event": map[string]any{"method": "GET", "path": "/private", "phase": "request"}}, false)
	if !bytes.Contains(decision, []byte(`"verdict":"deny"`)) || dst.writes.Load() != 0 {
		t.Fatalf("unsafe/wrong replay: %s writes=%d", decision, dst.writes.Load())
	}
	args := map[string]any{"revision": staged.Revision, "expected_revision": initial, "idempotency_key": "mcp-activate"}
	tool(t, client, web.URL, "activate_policy_deployment", args, false)
	tool(t, client, web.URL, "activate_policy_deployment", args, false)
	if dst.writes.Load() != 1 {
		t.Fatal("MCP idempotency failed")
	}
	tool(t, client, web.URL, "rollback_policy_deployment", map[string]any{"expected_revision": staged.Revision, "idempotency_key": "mcp-rollback"}, false)
	tool(t, client, web.URL, "query_policy_audit", map[string]any{"limit": 10}, false)
	if dst.Policy().Revision() != initial || dst.writes.Load() != 2 {
		t.Fatal("MCP rollback failed")
	}
}

func TestMCPReadOnlyMutationDenial(t *testing.T) {
	s, dst := service(t, false)
	web := httptest.NewServer(s.Handler())
	defer web.Close()
	rpc(t, web.Client(), web.URL, "initialize", map[string]any{"protocolVersion": "2025-03-26", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "read-only-test", "version": "1"}})
	for _, name := range []string{"stage_policy_revision", "activate_policy_deployment", "rollback_policy_deployment"} {
		result := tool(t, web.Client(), web.URL, name, map[string]any{"bundle": bundle("denied"), "revision": "missing", "expected_revision": dst.Policy().Revision(), "idempotency_key": "denied"}, true)
		if !bytes.Contains(result, []byte("read-only")) {
			t.Fatalf("wrong denial: %s", result)
		}
	}
	if dst.writes.Load() != 0 {
		t.Fatal("read-only MCP mutated target")
	}
}

func TestAuditAndReceiptRetention(t *testing.T) {
	s, _ := service(t, true)
	r := Request{Bundle: bundle("retention"), IdempotencyKey: "oldest"}
	exec(t, s, "stage", r)
	// Fill a high-water fixture in one transaction, then exercise production
	// pruning on the next mutation without thousands of physical fsyncs.
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	for i := range MaxAudit + 1 {
		if _, err = tx.Exec(`INSERT INTO audit(time,operation,revision,previous) VALUES('2026-01-01T00:00:00Z','stage','fixture','')`); err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(`INSERT INTO receipts(key,fingerprint,response) VALUES(?, 'fixture', '{}')`, fmt.Sprint("fixture-", i)); err != nil {
			t.Fatal(err)
		}
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	r.IdempotencyKey = "prune-high-water"
	exec(t, s, "stage", r)
	for table, max := range map[string]int{"audit": MaxAudit, "receipts": MaxReceipts} {
		var count int
		if err := s.db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != max {
			t.Fatalf("%s retained %d, want %d", table, count, max)
		}
	}
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM receipts WHERE key='oldest'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("old receipt retained outside advertised window")
	}
}

func TestCancellationAndBounds(t *testing.T) {
	s, dst := service(t, true)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := s.Execute(ctx, "stage", Request{Bundle: bundle("cancel"), IdempotencyKey: "cancel"})
	wantStatus(t, err, 408)
	_, err = s.Execute(context.Background(), "check", Request{Bundle: strings.Repeat("x", MaxInputBytes)})
	wantStatus(t, err, 413)
	for range 8 {
		s.slots <- struct{}{}
	}
	_, err = s.Execute(context.Background(), "capabilities", Request{})
	wantStatus(t, err, 429)
	for range 8 {
		<-s.slots
	}
	if dst.writes.Load() != 0 {
		t.Fatal("cancelled request mutated target")
	}
	r := &lineLimitReader{reader: strings.NewReader(strings.Repeat("x", MaxInputBytes+1))}
	_, err = io.Copy(io.Discard, r)
	if err == nil {
		t.Fatal("oversize stdio line accepted")
	}
}

func TestRevisionRetention(t *testing.T) {
	s, dst := service(t, true)
	initial := dst.Policy().Revision()
	first := stage(t, s, "first")
	exec(t, s, "activate", Request{Revision: first, ExpectedRevision: initial, IdempotencyKey: "activate-first"})
	for i := range MaxRevisions + 4 {
		stage(t, s, fmt.Sprint("retained-", i))
	}
	var revs []string
	if err := json.Unmarshal(exec(t, s, "revisions", Request{}), &revs); err != nil {
		t.Fatal(err)
	}
	if len(revs) > MaxRevisions {
		t.Fatalf("retained %d revisions", len(revs))
	}
	exec(t, s, "revision", Request{Revision: initial})
	exec(t, s, "revision", Request{Revision: first})
}
