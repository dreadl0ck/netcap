package firewallfleet

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/firewallstate"
	"github.com/dreadl0ck/netcap/internal/policy"
)

const effectsBundle = `{"version":"1","id":"effects","mode":"enforce","default":"allow","rules":[{"id":"block","expression":"true","action":"deny","effects":[{"kind":"block_source","duration":"1m","target":"client","scope":"broker-grant-required"}]}]}`

func TestEffectsAdmissionStageReloadRestoreAndCapabilities(t *testing.T) {
	cfg := fleetConfig(t)
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Execute(context.Background(), "tenant-a-admin-token", "stage", Request{Bundle: effectsBundle}); err == nil {
		t.Fatal("effects admitted by default")
	}
	if _, err = decodeOperation("stage", []byte(`{"bundle":"{}","allow_effects":true}`)); err == nil {
		t.Fatal("request widened bootstrap admission")
	}
	_ = s.Close()
	cfg.AllowEffects = true
	s, err = New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	result, err := s.Execute(context.Background(), "tenant-a-admin-token", "stage", Request{Bundle: effectsBundle})
	if err != nil {
		t.Fatal(err)
	}
	rev := result.(map[string]string)["revision"]
	rollout(t, s, "effects", rev, map[string]int64{"a": 0, "b": 0}, nil)
	execute(t, s, "activate", Request{ID: "effects", ExpectedPhase: "staged"})
	caps := execute(t, s, "capabilities", Request{}).(map[string]any)
	if caps["allow_effects"] != true {
		t.Fatal("capabilities concealed admission")
	}
	d, err := s.Desired(context.Background(), targetToken)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = verifyDesired(d, AgentConfig{TargetID: "a", Scope: scopeA}); err == nil {
		t.Fatal("agent admitted effects by default")
	}
	c, _, err := verifyDesired(d, AgentConfig{TargetID: "a", Scope: scopeA, AllowEffects: true})
	if err != nil {
		t.Fatal(err)
	}
	decision, err := c.Evaluate(policy.Event{ClientIP: "192.0.2.1"})
	if err != nil || len(decision.Effects) != 1 || decision.Effects[0].Scope != "broker-grant-required" {
		t.Fatalf("inert intent scope changed %+v %v", decision, err)
	}
	backup := filepath.Join(t.TempDir(), "backup", "fleet.sqlite")
	if err = s.Backup(context.Background(), backup); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	cfg.AllowEffects = false
	if _, err = New(cfg); err == nil {
		t.Fatal("effects snapshot loaded after admission downgrade")
	}
	dir := filepath.Join(t.TempDir(), "restored")
	if err = firewallstate.Restore(context.Background(), backup, dir, "fleet"); err != nil {
		t.Fatal(err)
	}
	cfg.StateDir = dir
	if _, err = New(cfg); err == nil {
		t.Fatal("restore bypassed admission")
	}
	cfg.AllowEffects = true
	s, err = New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
}

func TestEffectsAgentCacheCannotCrossAdmissionBinding(t *testing.T) {
	cfg := fleetConfig(t)
	cfg.AllowEffects = true
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	rev := execute(t, s, "stage", Request{Bundle: effectsBundle}).(map[string]string)["revision"]
	rollout(t, s, "effects", rev, map[string]int64{"a": 0, "b": 0}, nil)
	execute(t, s, "activate", Request{ID: "effects", ExpectedPhase: "staged"})
	srv := httptest.NewServer(s.Handler())
	agent := AgentConfig{URL: srv.URL, Token: targetToken, TargetID: "a", Scope: scopeA, AllowEffects: true, StateDir: filepath.Join(t.TempDir(), "agent"), PollInterval: 20 * time.Millisecond}
	target := &atomicTarget{}
	statuses, stop := startAgent(t, agent, target)
	awaitStatus(t, statuses, func(s AgentStatus) bool { return s.Ready && s.Error == "" })
	stop()
	srv.Close()
	agent.AllowEffects = false
	cold := &atomicTarget{}
	statuses, stop = startAgent(t, agent, cold)
	awaitStatus(t, statuses, func(s AgentStatus) bool { return !s.Ready && strings.Contains(s.Error, "identity") })
	stop()
	if cold.Policy() != nil {
		t.Fatal("effects cache survived allow-effects downgrade")
	}
	// Rebinding the cache identity alone cannot forge its existing MAC.
	path := filepath.Join(agent.StateDir, "agent-cache.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var record cacheRecord
	if err = json.Unmarshal(raw, &record); err != nil {
		t.Fatal(err)
	}
	record.Binding = agentBinding(agent)
	raw, _ = json.Marshal(record)
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	statuses, stop = startAgent(t, agent, cold)
	awaitStatus(t, statuses, func(s AgentStatus) bool { return !s.Ready && strings.Contains(s.Error, "integrity") })
	stop()
}

func TestDurableDrainRevokeResumeAndScope(t *testing.T) {
	cfg := fleetConfig(t)
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	rev := stage(t, s, "baseline", "allow")
	rollout(t, s, "baseline", rev, map[string]int64{"a": 0, "b": 0}, nil)
	execute(t, s, "activate", Request{ID: "baseline", ExpectedPhase: "staged"})
	execute(t, s, "drain", Request{Targets: []string{"a"}, Expected: map[string]int64{"a": 1}})
	d, err := s.Desired(context.Background(), targetToken)
	if err != nil || !d.Draining || d.Revoked || len(d.Bundle) != 0 || d.Generation != 2 {
		t.Fatalf("drain %+v %v", d, err)
	}
	if err = s.Acknowledge(context.Background(), targetToken, Ack{Revision: rev, Generation: 2}); err == nil {
		t.Fatal("policy ack impersonated drain receipt")
	}
	if err = s.Acknowledge(context.Background(), targetToken, Ack{Revision: rev, Generation: 2, Draining: true}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Execute(context.Background(), "tenant-a-admin-token", "revoke", Request{Scope: scopeB, Targets: []string{"foreign"}, Expected: map[string]int64{"foreign": 0}}); err == nil {
		t.Fatal("cross-scope revoke accepted")
	}
	execute(t, s, "revoke", Request{Targets: []string{"a"}, Expected: map[string]int64{"a": 2}})
	_ = s.Close()
	s, err = New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	d, err = s.Desired(context.Background(), targetToken)
	if err != nil || !d.Revoked || !d.Draining || d.Generation != 3 || len(d.Bundle) != 0 {
		t.Fatalf("revoke not durable %+v %v", d, err)
	}
	if _, err = s.Execute(context.Background(), adminToken, "resume", Request{Scope: scopeA, Targets: []string{"a"}, Expected: map[string]int64{"a": 2}}); err == nil {
		t.Fatal("stale resume accepted")
	}
	execute(t, s, "resume", Request{Targets: []string{"a"}, Expected: map[string]int64{"a": 3}})
	d, err = s.Desired(context.Background(), targetToken)
	if err != nil || d.Draining || d.Revoked || d.Generation != 4 || d.Revision != rev {
		t.Fatalf("resume %+v %v", d, err)
	}
}

func TestRevocationPersistsInAgentCacheAndOmittedEnrollment(t *testing.T) {
	cfg := fleetConfig(t)
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	rev := stage(t, s, "baseline", "allow")
	rollout(t, s, "baseline", rev, map[string]int64{"a": 0, "b": 0}, nil)
	execute(t, s, "activate", Request{ID: "baseline", ExpectedPhase: "staged"})
	_ = s.Close()
	cfg.Targets = cfg.Targets[1:]
	s, err = New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	srv := httptest.NewServer(s.Handler())
	agent := AgentConfig{URL: srv.URL, Token: targetToken, TargetID: "a", Scope: scopeA, StateDir: filepath.Join(t.TempDir(), "agent"), PollInterval: 20 * time.Millisecond}
	target := &atomicTarget{}
	statuses, stop := startAgent(t, agent, target)
	awaitStatus(t, statuses, func(s AgentStatus) bool { return !s.Ready && s.Revoked && s.Generation == 2 && s.Error == "" })
	stop()
	if target.Policy() != nil {
		t.Fatal("revoked target received policy")
	}
	srv.Close()
	statuses, stop = startAgent(t, agent, &atomicTarget{})
	awaitStatus(t, statuses, func(s AgentStatus) bool { return !s.Ready && s.Revoked && s.Draining && s.Generation == 2 })
	stop()
}

func initializedFleet(t *testing.T) (*Service, Config, string) {
	t.Helper()
	cfg := fleetConfig(t)
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	baseline := stage(t, s, "baseline", "allow")
	rollout(t, s, "baseline", baseline, map[string]int64{"a": 0, "b": 0}, nil)
	execute(t, s, "activate", Request{ID: "baseline", ExpectedPhase: "staged"})
	ack(t, s, targetToken)
	ack(t, s, cfg.Targets[1].Token)
	return s, cfg, baseline
}
func guardedCanary(t *testing.T, s *Service, id string) string {
	t.Helper()
	rev := stage(t, s, id, "deny")
	execute(t, s, "rollout", Request{ID: id, Revision: rev, Targets: []string{"a", "b"}, Canary: []string{"a"}, Expected: map[string]int64{"a": 1, "b": 1}, Deadline: time.Now().Add(time.Hour), RollbackOnFailure: true})
	execute(t, s, "activate", Request{ID: id, ExpectedPhase: "staged"})
	return rev
}
func TestAutomaticHealthRollbackAndPersistence(t *testing.T) {
	s, cfg, baseline := initializedFleet(t)
	rev := guardedCanary(t, s, "bad")
	if err := s.Acknowledge(context.Background(), targetToken, Ack{Revision: rev, Generation: 2, Error: "health failed"}); err != nil {
		t.Fatal(err)
	}
	status := execute(t, s, "status", Request{}).(Status)
	var job *Job
	for _, j := range status.Jobs {
		if j.ID == "bad" {
			job = j
		}
	}
	if job == nil || job.Phase != "rolledback" || job.Failure == "" || status.Targets["a"].Generation != 3 || status.Targets["a"].DesiredRevision != baseline || status.Targets["b"].Generation != 1 {
		t.Fatalf("rollback %+v %+v", job, status.Targets)
	}
	_ = s.Close()
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	d, err := s.Desired(context.Background(), targetToken)
	if err != nil || d.Generation != 3 || d.Revision != baseline || !d.Deadline.After(time.Now()) {
		t.Fatalf("durable rollback %+v %v", d, err)
	}
	audits := execute(t, s, "audit", Request{}).([]Audit)
	found := false
	for _, a := range audits {
		if a.Operation == "auto_rollback" && a.Scope == scopeA {
			found = true
		}
	}
	if !found {
		t.Fatal("missing rollback audit")
	}
}
func TestAutomaticDeadlineRollbackAndConflict(t *testing.T) {
	for _, conflict := range []bool{false, true} {
		t.Run(map[bool]string{false: "deadline", true: "control-conflict"}[conflict], func(t *testing.T) {
			s, _, baseline := initializedFleet(t)
			defer s.Close()
			guardedCanary(t, s, "deadline")
			if conflict {
				execute(t, s, "drain", Request{Targets: []string{"a"}, Expected: map[string]int64{"a": 2}})
			}
			s.mu.Lock()
			err := s.transaction(context.Background(), func(st *snapshot) error { st.Jobs["deadline"].Deadline = time.Now().Add(-time.Second); return nil })
			s.mu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			result, err := s.Maintain(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			status := execute(t, s, "status", Request{}).(Status)
			if conflict {
				if len(result.Blocked) != 1 || !status.Targets["a"].Draining || status.Targets["a"].Generation != 3 {
					t.Fatalf("CAS conflict overwritten %+v %+v", result, status.Targets)
				}
			} else {
				if len(result.RolledBack) != 1 || status.Targets["a"].DesiredRevision != baseline || status.Targets["a"].Generation != 3 {
					t.Fatalf("deadline rollback %+v %+v", result, status.Targets)
				}
			}
			second, err := s.Maintain(context.Background())
			if err != nil || len(second.Blocked)+len(second.RolledBack) != 0 {
				t.Fatalf("maintenance repeated %+v %v", second, err)
			}
		})
	}
}

func TestConfiguredRollbackGateAndScopedMaintenance(t *testing.T) {
	s, cfg, baseline := initializedFleet(t)
	_ = s.Close()
	cfg.RollbackOnFailure = true
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	rev := stage(t, s, "canary", "deny")
	j := execute(t, s, "rollout", Request{ID: "canary", Revision: rev, Targets: []string{"a", "b"}, Canary: []string{"a"}, Expected: map[string]int64{"a": 1, "b": 1}, Deadline: time.Now().Add(time.Hour)}).(*Job)
	if !j.RollbackOnFailure {
		t.Fatal("request disabled configured rollback policy")
	}
	execute(t, s, "activate", Request{ID: "canary", ExpectedPhase: "staged"})
	s.mu.Lock()
	err = s.transaction(context.Background(), func(st *snapshot) error { st.Jobs["canary"].Deadline = time.Now().Add(-time.Second); return nil })
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Execute(context.Background(), adminToken, "status", Request{Scope: scopeB}); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	phase := ""
	err = s.transactionMode(context.Background(), false, func(st *snapshot) error { phase = st.Jobs["canary"].Phase; return nil })
	s.mu.Unlock()
	if err != nil || phase != "canary" {
		t.Fatal("foreign scope status drove rollback")
	}
	status := execute(t, s, "status", Request{}).(Status)
	if status.Targets["a"].DesiredRevision != baseline || status.Targets["a"].Generation != 3 {
		t.Fatal("scoped status did not persist deadline rollback")
	}
}

func TestHealthyActiveJobDoesNotRollbackAtDeadline(t *testing.T) {
	s, cfg, baseline := initializedFleet(t)
	defer s.Close()
	rev := guardedCanary(t, s, "healthy")
	ack(t, s, targetToken)
	execute(t, s, "promote", Request{ID: "healthy", ExpectedPhase: "canary"})
	ack(t, s, cfg.Targets[1].Token)
	s.mu.Lock()
	err := s.transaction(context.Background(), func(st *snapshot) error { st.Jobs["healthy"].Deadline = time.Now().Add(-time.Second); return nil })
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	result, err := s.Maintain(context.Background())
	if err != nil || len(result.RolledBack)+len(result.Blocked) != 0 {
		t.Fatalf("healthy job rolled back %+v %v", result, err)
	}
	if err = s.Acknowledge(context.Background(), targetToken, Ack{Revision: rev, Generation: 2, Error: "health failed after activation"}); err != nil {
		t.Fatal(err)
	}
	status := execute(t, s, "status", Request{}).(Status)
	for _, id := range []string{"a", "b"} {
		if status.Targets[id].DesiredRevision != baseline || status.Targets[id].Generation != 3 {
			t.Fatalf("full rollback missed %s %+v", id, status.Targets[id])
		}
	}
}

func TestAgentDrainPersistsAndCallsRuntimeBeforeReceipt(t *testing.T) {
	s, _, _ := initializedFleet(t)
	defer s.Close()
	execute(t, s, "revoke", Request{Targets: []string{"a"}, Expected: map[string]int64{"a": 1}})
	stateDir := filepath.Join(t.TempDir(), "agent")
	var draining, violation atomic.Bool
	received := make(chan struct{}, 1)
	handler := s.Handler()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/fleet/ack" {
			raw, err := os.ReadFile(filepath.Join(stateDir, "agent-cache.json"))
			var record cacheRecord
			if err != nil || json.Unmarshal(raw, &record) != nil || !record.Desired.Revoked || !draining.Load() {
				violation.Store(true)
			}
		}
		handler.ServeHTTP(w, r)
		if r.URL.Path == "/api/v1/fleet/ack" {
			select {
			case received <- struct{}{}:
			default:
			}
		}
	}))
	defer srv.Close()
	agent := AgentConfig{URL: srv.URL, Token: targetToken, TargetID: "a", Scope: scopeA, StateDir: stateDir, PollInterval: 20 * time.Millisecond, OnStatus: func(s AgentStatus) { draining.Store(s.Draining) }}
	_, stop := startAgent(t, agent, &atomicTarget{})
	defer stop()
	select {
	case <-received:
	case <-time.After(3 * time.Second):
		t.Fatal("drain receipt not received")
	}
	if violation.Load() {
		t.Fatal("drain receipt preceded persistence or runtime callback")
	}
	status := execute(t, s, "status", Request{}).(Status)
	if !status.Targets["a"].ObservedRevoked || !status.Targets["a"].ObservedDraining {
		t.Fatal("control receipt not observed")
	}
}

func TestAgentRequiresReadinessDrainHook(t *testing.T) {
	err := Run(context.Background(), AgentConfig{URL: "http://127.0.0.1:1", Token: targetToken, TargetID: "a", Scope: scopeA, StateDir: filepath.Join(t.TempDir(), "agent")}, &atomicTarget{})
	if err == nil || !strings.Contains(err.Error(), "OnStatus") {
		t.Fatal("agent ran without runtime readiness/drain hook")
	}
}
