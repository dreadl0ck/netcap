package firewallfleet

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/firewallstate"
	"github.com/dreadl0ck/netcap/internal/policy"
)

const adminToken = "fleet-administrator-secret"
const targetToken = "fleet-target-a-secret-token"

var scopeA = Scope{Tenant: "tenant-a", App: "app"}
var scopeB = Scope{Tenant: "tenant-b", App: "app"}

func fleetConfig(t *testing.T) Config {
	t.Helper()
	return Config{StateDir: filepath.Join(t.TempDir(), "fleet"), Token: adminToken, Identities: []Identity{{ID: "admin-a", Token: "tenant-a-admin-token", Scope: scopeA}}, Targets: []Enrollment{{ID: "a", Token: targetToken, Scope: scopeA}, {ID: "b", Token: "fleet-target-b-secret-token", Scope: scopeA}, {ID: "foreign", Token: "foreign-target-secret-token", Scope: scopeB}}}
}
func execute(t *testing.T, s *Service, op string, r Request) any {
	t.Helper()
	r.Scope = scopeA
	v, err := s.Execute(context.Background(), adminToken, op, r)
	if err != nil {
		t.Fatalf("%s: %v", op, err)
	}
	return v
}
func stage(t *testing.T, s *Service, id, def string) string {
	t.Helper()
	raw := `{"version":"1","id":"` + id + `","mode":"enforce","default":"` + def + `","rules":[]}`
	v := execute(t, s, "stage", Request{Bundle: raw}).(map[string]string)
	return v["revision"]
}
func rollout(t *testing.T, s *Service, id, rev string, expected map[string]int64, canary []string) {
	t.Helper()
	targets := []string{"a", "b"}
	execute(t, s, "rollout", Request{ID: id, Revision: rev, Targets: targets, Expected: expected, Canary: canary, Deadline: time.Now().Add(time.Hour)})
}
func ack(t *testing.T, s *Service, token string) {
	t.Helper()
	d, err := s.Desired(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Acknowledge(context.Background(), token, Ack{Revision: d.Revision, Generation: d.Generation}); err != nil {
		t.Fatal(err)
	}
}

func awaitObserved(t *testing.T, s *Service, id string, generation int64) Status {
	t.Helper()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		status := execute(t, s, "status", Request{}).(Status)
		if status.Targets[id].ObservedGeneration == generation {
			return status
		}
		select {
		case <-deadline.C:
			t.Fatalf("target %s did not acknowledge generation %d", id, generation)
		case <-tick.C:
		}
	}
}
func TestCanaryCASRollbackRestart(t *testing.T) {
	cfg := fleetConfig(t)
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	rev1 := stage(t, s, "one", "allow")
	rollout(t, s, "initial", rev1, map[string]int64{"a": 0, "b": 0}, nil)
	execute(t, s, "activate", Request{ID: "initial", ExpectedPhase: "staged"})
	ack(t, s, targetToken)
	ack(t, s, cfg.Targets[1].Token)
	rev2 := stage(t, s, "two", "deny")
	rollout(t, s, "canary", rev2, map[string]int64{"a": 1, "b": 1}, []string{"a"})
	execute(t, s, "activate", Request{ID: "canary", ExpectedPhase: "staged"})
	if _, err = s.Execute(context.Background(), adminToken, "promote", Request{Scope: scopeA, ID: "canary", ExpectedPhase: "canary"}); err == nil {
		t.Fatal("unobserved canary promoted")
	}
	if err = s.Acknowledge(context.Background(), targetToken, Ack{Revision: rev1, Generation: 1}); err == nil {
		t.Fatal("stale ack accepted")
	}
	ack(t, s, targetToken)
	execute(t, s, "promote", Request{ID: "canary", ExpectedPhase: "canary"})
	ack(t, s, cfg.Targets[1].Token)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err = s.WaitConverged(ctx, adminToken, scopeA, "canary"); err != nil {
		t.Fatal(err)
	}
	execute(t, s, "rollback", Request{ID: "canary", ExpectedPhase: "active"})
	d, err := s.Desired(context.Background(), targetToken)
	if err != nil || d.Revision != rev1 || d.Generation != 3 {
		t.Fatalf("rollback %+v %v", d, err)
	}
	if _, err = New(cfg); err == nil {
		t.Fatal("second controller accepted")
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	d, err = s.Desired(context.Background(), targetToken)
	if err != nil || d.Generation != 3 || d.Revision != rev1 {
		t.Fatalf("restart %+v %v", d, err)
	}
	status := execute(t, s, "status", Request{}).(Status)
	if len(status.Targets) != 2 || status.Targets["a"].TokenHash != "" {
		t.Fatalf("foreign target/hash leaked %+v", status)
	}
}
func TestConcurrentRolloutCAS(t *testing.T) {
	s, err := New(fleetConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	rev := stage(t, s, "one", "allow")
	rollout(t, s, "first", rev, map[string]int64{"a": 0, "b": 0}, nil)
	rollout(t, s, "second", rev, map[string]int64{"a": 0, "b": 0}, nil)
	var successes atomic.Int32
	var wg sync.WaitGroup
	for _, id := range []string{"first", "second"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, e := s.Execute(context.Background(), adminToken, "activate", Request{Scope: scopeA, ID: id, ExpectedPhase: "staged"}); e == nil {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatalf("CAS winners %d", successes.Load())
	}
	d, e := s.Desired(context.Background(), targetToken)
	if e != nil || d.Generation != 1 {
		t.Fatalf("generation %+v %v", d, e)
	}
}
func TestForeignAuthAndServerBoundAttachments(t *testing.T) {
	cfg := fleetConfig(t)
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	rev := stage(t, s, "one", "allow")
	for _, tc := range []struct {
		token string
		op    string
		r     Request
	}{{targetToken, "stage", Request{Scope: scopeA, Bundle: `{}`}}, {"tenant-a-admin-token", "status", Request{Scope: scopeB}}, {adminToken, "rollout", Request{Scope: scopeA, ID: "foreign", Revision: rev, Targets: []string{"foreign"}, Expected: map[string]int64{"foreign": 0}, Deadline: time.Now().Add(time.Hour)}}} {
		if _, err = s.Execute(context.Background(), tc.token, tc.op, tc.r); err == nil {
			t.Fatalf("foreign operation accepted %+v", tc)
		}
	}
	for _, tc := range []struct {
		path, body string
		status     int
	}{{"/api/v1/fleet/desired?target_id=b", "", 400}, {"/api/v1/fleet/ack", `{"revision":"x","generation":1,"target_id":"b"}`, 400}} {
		method := "POST"
		if tc.body == "" {
			method = "GET"
		}
		r := httptest.NewRequest(method, tc.path, strings.NewReader(tc.body))
		r.Header.Set("Authorization", "Bearer "+targetToken)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatalf("%s returned %d %s", tc.path, w.Code, w.Body.String())
		}
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	cfg.Targets[0].Scope = scopeB
	if _, err = New(cfg); err == nil {
		t.Fatal("target rebound to foreign scope")
	}
}
func TestDeadlineAndPersistedGenerationValidation(t *testing.T) {
	cfg := fleetConfig(t)
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	rev := stage(t, s, "one", "allow")
	rollout(t, s, "expired", rev, map[string]int64{"a": 0, "b": 0}, nil)
	s.mu.Lock()
	err = s.transaction(context.Background(), func(st *snapshot) error { st.Jobs["expired"].Deadline = time.Now().Add(-time.Second); return nil })
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Execute(context.Background(), adminToken, "activate", Request{Scope: scopeA, ID: "expired", ExpectedPhase: "staged"}); err == nil {
		t.Fatal("expired job activated")
	}
	s.mu.Lock()
	err = s.transaction(context.Background(), func(st *snapshot) error { st.Targets["a"].Generation = 7; return nil })
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	if _, err = New(cfg); err == nil {
		t.Fatal("invalid desired generation reloaded")
	}
}

func TestMCPActualDescriptorsAndCalls(t *testing.T) {
	s, err := New(fleetConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	rpc := func(body, token string) map[string]json.RawMessage {
		t.Helper()
		r, _ := http.NewRequest("POST", srv.URL+"/mcp", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept", "application/json, text/event-stream")
		resp, e := srv.Client().Do(r)
		if e != nil {
			t.Fatal(e)
		}
		defer resp.Body.Close()
		var out map[string]json.RawMessage
		if e = json.NewDecoder(resp.Body).Decode(&out); e != nil {
			t.Fatal(e)
		}
		return out
	}
	out := rpc(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`, adminToken)
	if out["error"] != nil {
		t.Fatalf("initialize %s", out["error"])
	}
	out = rpc(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`, adminToken)
	var listed struct {
		Tools []struct {
			Name   string `json:"name"`
			Schema struct {
				Type       string         `json:"type"`
				Properties map[string]any `json:"properties"`
				Additional bool           `json:"additionalProperties"`
			} `json:"inputSchema"`
		} `json:"tools"`
	}
	if err = json.Unmarshal(out["result"], &listed); err != nil {
		t.Fatalf("tools/list %s %v", out["error"], err)
	}
	if len(listed.Tools) != len(descriptors) {
		t.Fatalf("tools %d", len(listed.Tools))
	}
	for _, tool := range listed.Tools {
		d, ok := descriptorFor(strings.TrimPrefix(tool.Name, "fleet_"))
		if !ok || tool.Schema.Type != "object" || tool.Schema.Additional || len(tool.Schema.Properties) != len(d.fields) {
			t.Fatalf("descriptor %+v", tool)
		}
	}
	out = rpc(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"fleet_status","arguments":{"scope":{"tenant":"tenant-a","app":"app"}}}}`, adminToken)
	if out["error"] != nil || strings.Contains(string(out["result"]), `"isError":true`) {
		t.Fatalf("tools/call %+v", out)
	}
	out = rpc(`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"fleet_stage","arguments":{"bundle":"{}","target_id":"foreign"}}}`, "tenant-a-admin-token")
	if !strings.Contains(string(out["result"]), `"isError":true`) {
		t.Fatalf("extra argument accepted %+v", out)
	}
}

type atomicTarget struct {
	ptr atomic.Pointer[policy.Compiled]
}

func (t *atomicTarget) Policy() *policy.Compiled     { return t.ptr.Load() }
func (t *atomicTarget) SetPolicy(c *policy.Compiled) { t.ptr.Store(c) }
func startAgent(t *testing.T, cfg AgentConfig, target *atomicTarget) (<-chan AgentStatus, func()) {
	t.Helper()
	statuses := make(chan AgentStatus, 64)
	onStatus := cfg.OnStatus
	cfg.OnStatus = func(s AgentStatus) {
		if onStatus != nil {
			onStatus(s)
		}
		select {
		case statuses <- s:
		default:
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg, target) }()
	return statuses, func() {
		cancel()
		select {
		case err := <-done:
			if err != nil && err != context.Canceled {
				t.Errorf("agent: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("agent cancellation unbounded")
		}
	}
}
func awaitStatus(t *testing.T, ch <-chan AgentStatus, predicate func(AgentStatus) bool) AgentStatus {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for {
		select {
		case s := <-ch:
			if predicate(s) {
				return s
			}
		case <-deadline.C:
			t.Fatal("agent status timed out")
			return AgentStatus{}
		}
	}
}
func TestAgentAppliesBeforeAckAndCacheRecovery(t *testing.T) {
	s, err := New(fleetConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	rev := stage(t, s, "one", "allow")
	rollout(t, s, "initial", rev, map[string]int64{"a": 0, "b": 0}, nil)
	execute(t, s, "activate", Request{ID: "initial", ExpectedPhase: "staged"})
	target := &atomicTarget{}
	var ackBeforeApply atomic.Bool
	handler := s.Handler()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/fleet/ack" && (target.Policy() == nil || target.Policy().Revision() != rev) {
			ackBeforeApply.Store(true)
		}
		handler.ServeHTTP(w, r)
	}))
	cfg := AgentConfig{URL: srv.URL, Token: targetToken, TargetID: "a", Scope: scopeA, StateDir: filepath.Join(t.TempDir(), "agent"), PollInterval: 20 * time.Millisecond, RequestTimeout: 100 * time.Millisecond}
	statuses, stop := startAgent(t, cfg, target)
	awaitStatus(t, statuses, func(s AgentStatus) bool { return s.Ready && s.Generation == 1 && s.Error == "" })
	awaitObserved(t, s, "a", 1)
	stop()
	if ackBeforeApply.Load() {
		t.Fatal("ack preceded atomic apply")
	}
	path := filepath.Join(cfg.StateDir, "agent-cache.json")
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("cache permissions %v %v", info, err)
	}
	srv.Close()
	target = &atomicTarget{}
	statuses, stop = startAgent(t, cfg, target)
	awaitStatus(t, statuses, func(s AgentStatus) bool { return s.Ready && s.Generation == 1 })
	stop()
	if target.Policy() == nil || target.Policy().Revision() != rev {
		t.Fatal("cache not applied during outage")
	}
	cfg.MaxStale = time.Millisecond
	time.Sleep(2 * time.Millisecond)
	statuses, stop = startAgent(t, cfg, &atomicTarget{})
	awaitStatus(t, statuses, func(s AgentStatus) bool { return !s.Ready && s.Generation == 1 })
	stop()
	// Even a valid cache cannot cross token/target identity bindings.
	cfg.Token = "different-target-secret-token"
	cold := &atomicTarget{}
	statuses, stop = startAgent(t, cfg, cold)
	awaitStatus(t, statuses, func(s AgentStatus) bool { return !s.Ready && strings.Contains(s.Error, "identity") })
	stop()
	if cold.Policy() != nil {
		t.Fatal("foreign cache applied")
	}
	cfg.Token = targetToken
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var record cacheRecord
	if err = json.Unmarshal(raw, &record); err != nil {
		t.Fatal(err)
	}
	record.Desired.Generation++
	raw, _ = json.Marshal(record)
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	cold = &atomicTarget{}
	statuses, stop = startAgent(t, cfg, cold)
	awaitStatus(t, statuses, func(s AgentStatus) bool { return !s.Ready && strings.Contains(s.Error, "integrity") })
	stop()
	if cold.Policy() != nil {
		t.Fatal("tampered cache applied")
	}
}
func TestDesiredIntegrity(t *testing.T) {
	cfg := AgentConfig{TargetID: "a", Scope: scopeA}
	c, raw, err := compile([]byte(`{"version":"1","id":"one","mode":"enforce","default":"allow"}`))
	if err != nil {
		t.Fatal(err)
	}
	d := Desired{Version: 1, TargetID: "a", Scope: scopeA, Generation: 1, Revision: c.Revision(), Hash: firewallstate.Digest(string(raw)), Bundle: raw}
	if _, _, err = verifyDesired(d, cfg); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Desired){func(d *Desired) { d.Hash = "bad" }, func(d *Desired) { d.Version = 2 }, func(d *Desired) { d.Scope = scopeB }, func(d *Desired) { d.Generation = 0 }, func(d *Desired) { d.Revision = firewallstate.Digest("wrong") }} {
		copy := d
		mutate(&copy)
		if _, _, err = verifyDesired(copy, cfg); err == nil {
			t.Fatal("invalid desired accepted")
		}
	}
}

func TestFleetBackupRestoreAndArtifactIntegrity(t *testing.T) {
	cfg := fleetConfig(t)
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	rev := stage(t, s, "one", "allow")
	rollout(t, s, "initial", rev, map[string]int64{"a": 0, "b": 0}, nil)
	execute(t, s, "activate", Request{ID: "initial", ExpectedPhase: "staged"})
	ack(t, s, targetToken)
	backup := filepath.Join(t.TempDir(), "private", "fleet.sqlite")
	if err = s.Backup(context.Background(), backup); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	dir := filepath.Join(t.TempDir(), "restored")
	if err = firewallstate.Restore(context.Background(), backup, dir, "fleet"); err != nil {
		t.Fatal(err)
	}
	cfg.StateDir = dir
	s, err = New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	d, err := s.Desired(context.Background(), targetToken)
	if err != nil || d.Generation != 1 || d.Revision != rev {
		t.Fatalf("restored desired %+v %v", d, err)
	}
	// A durable artifact with a replaced body must fail validation on reload.
	if _, err = s.disk.DB.Exec(`UPDATE artifacts SET bundle=?`, []byte(`{"version":"1","id":"tampered","mode":"enforce","default":"deny"}`)); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	if _, err = New(cfg); err == nil {
		t.Fatal("tampered artifact loaded")
	}
}

func TestAgentRejectsControllerRegressionAndBadHash(t *testing.T) {
	c, raw, err := compile([]byte(`{"version":"1","id":"stable","mode":"enforce","default":"deny"}`))
	if err != nil {
		t.Fatal(err)
	}
	d := Desired{Version: 1, TargetID: "a", Scope: scopeA, Generation: 2, Revision: c.Revision(), Hash: firewallstate.Digest(string(raw)), Bundle: raw, Deadline: time.Now().Add(time.Hour)}
	var desired atomic.Pointer[Desired]
	desired.Store(&d)
	var acknowledgments atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/fleet/desired" {
			firewallstate.WriteJSON(w, 200, desired.Load())
			return
		}
		acknowledgments.Add(1)
		firewallstate.WriteJSON(w, 200, map[string]bool{"accepted": true})
	}))
	defer srv.Close()
	cfg := AgentConfig{URL: srv.URL, Token: targetToken, TargetID: "a", Scope: scopeA, StateDir: filepath.Join(t.TempDir(), "agent"), PollInterval: 20 * time.Millisecond}
	target := &atomicTarget{}
	statuses, stop := startAgent(t, cfg, target)
	defer stop()
	awaitStatus(t, statuses, func(s AgentStatus) bool { return s.Ready && s.Generation == 2 && s.Error == "" })
	lower := d
	lower.Generation = 1
	desired.Store(&lower)
	awaitStatus(t, statuses, func(s AgentStatus) bool { return strings.Contains(s.Error, "regression") })
	if target.Policy().Revision() != d.Revision {
		t.Fatal("regression changed target")
	}
	before := acknowledgments.Load()
	cc, changed, err := compile([]byte(`{"version":"1","id":"equivocation","mode":"enforce","default":"allow"}`))
	if err != nil {
		t.Fatal(err)
	}
	equal := d
	equal.Bundle = changed
	equal.Hash = firewallstate.Digest(string(changed))
	equal.Revision = cc.Revision()
	desired.Store(&equal)
	awaitStatus(t, statuses, func(s AgentStatus) bool { return strings.Contains(s.Error, "equivocation") })
	if target.Policy().Revision() != d.Revision || acknowledgments.Load() != before {
		t.Fatal("equal-generation different digest changed or acknowledged policy")
	}
	bad := d
	bad.Generation = 3
	bad.Hash = firewallstate.Digest("foreign")
	desired.Store(&bad)
	awaitStatus(t, statuses, func(s AgentStatus) bool { return strings.Contains(s.Error, "hash") })
	if acknowledgments.Load() != before {
		t.Fatal("invalid desired state acknowledged")
	}
}

func TestAgentLiveRevisionUpdate(t *testing.T) {
	s, err := New(fleetConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	rev := stage(t, s, "initial", "allow")
	rollout(t, s, "initial", rev, map[string]int64{"a": 0, "b": 0}, nil)
	execute(t, s, "activate", Request{ID: "initial", ExpectedPhase: "staged"})
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	target := &atomicTarget{}
	cfg := AgentConfig{URL: srv.URL, Token: targetToken, TargetID: "a", Scope: scopeA, StateDir: filepath.Join(t.TempDir(), "agent"), PollInterval: 20 * time.Millisecond}
	statuses, stop := startAgent(t, cfg, target)
	defer stop()
	awaitStatus(t, statuses, func(s AgentStatus) bool { return s.Ready && s.Generation == 1 && s.Error == "" })
	rev2 := stage(t, s, "second", "deny")
	rollout(t, s, "second", rev2, map[string]int64{"a": 1, "b": 1}, nil)
	execute(t, s, "activate", Request{ID: "second", ExpectedPhase: "staged"})
	awaitStatus(t, statuses, func(s AgentStatus) bool { return s.Ready && s.Generation == 2 && s.Error == "" })
	d, err := target.Policy().Evaluate(policy.Event{})
	if err != nil || d.Verdict != "deny" || d.Revision != rev2 {
		t.Fatalf("updated decision %+v %v", d, err)
	}
	st := awaitObserved(t, s, "a", 2)
	if st.Targets["a"].ObservedGeneration != 2 || st.Targets["b"].ObservedGeneration != 0 {
		t.Fatalf("observations %+v", st.Targets)
	}
}

func TestAgentCacheWriteFailureDrainsWithoutAck(t *testing.T) {
	s, err := New(fleetConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	rev := stage(t, s, "initial", "allow")
	rollout(t, s, "initial", rev, map[string]int64{"a": 0, "b": 0}, nil)
	execute(t, s, "activate", Request{ID: "initial", ExpectedPhase: "staged"})
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	target := &atomicTarget{}
	cfg := AgentConfig{URL: srv.URL, Token: targetToken, TargetID: "a", Scope: scopeA, StateDir: filepath.Join(t.TempDir(), "agent"), PollInterval: 100 * time.Millisecond}
	statuses, stop := startAgent(t, cfg, target)
	defer stop()
	awaitStatus(t, statuses, func(s AgentStatus) bool { return s.Ready && s.Generation == 1 && s.Error == "" })
	awaitObserved(t, s, "a", 1)
	path := filepath.Join(cfg.StateDir, "agent-cache.json")
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	rev2 := stage(t, s, "second", "deny")
	rollout(t, s, "second", rev2, map[string]int64{"a": 1, "b": 1}, nil)
	execute(t, s, "activate", Request{ID: "second", ExpectedPhase: "staged"})
	awaitStatus(t, statuses, func(s AgentStatus) bool { return !s.Ready && s.Generation == 2 && s.Error != "" })
	if target.Policy().Revision() != rev2 {
		t.Fatal("new policy not applied before persistence failure")
	}
	status := execute(t, s, "status", Request{}).(Status)
	if status.Targets["a"].ObservedGeneration != 1 {
		t.Fatal("unpersisted policy acknowledged")
	}
}
