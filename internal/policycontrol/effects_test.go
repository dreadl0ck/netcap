package policycontrol

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/dreadl0ck/netcap/internal/policy"
)

const effectsBundle = `{"version":"1","id":"effects","mode":"enforce","default":"allow","rules":[{"id":"deny","expression":"true","action":"deny","effects":[{"kind":"block_source","target":"client","duration":"1m","scope":"edge"}]}]}`

func admittedPolicy(t *testing.T) *policy.Compiled {
	t.Helper()
	c, _, err := compileAdmitted([]byte(effectsBundle), true)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestEffectsAdmissionDefaultAndFileReload(t *testing.T) {
	for _, managed := range []bool{false, true} {
		dst := target(t)
		s, err := New(Config{Token: "secret", Managed: managed, StateDir: filepath.Join(t.TempDir(), "state")}, dst)
		if err != nil {
			t.Fatal(err)
		}
		for _, op := range []string{"check", "stage"} {
			_, err = s.Execute(context.Background(), op, Request{Bundle: effectsBundle, IdempotencyKey: "effects"})
			status := 400
			if op == "stage" && !managed {
				status = 403
			}
			wantStatus(t, err, status)
		}
		// File/GitOps owners can replace Target externally; reads must readmit it.
		dst.current.Store(admittedPolicy(t))
		for _, op := range []string{"evaluate", "revision"} {
			_, err = s.Execute(context.Background(), op, Request{Event: policy.Event{ClientIP: "192.0.2.5"}})
			wantStatus(t, err, 400)
		}
		_ = s.Close()
		if leaked, err := New(Config{Token: "secret"}, dst); err == nil {
			_ = leaked.Close()
			t.Fatal("unadmitted initial file policy accepted")
		}
	}
}

func TestEffectsControlLifecycleRecoveryAndInertReplay(t *testing.T) {
	dst := target(t)
	initial := dst.Policy().Revision()
	cfg := Config{Token: "secret", Managed: true, AllowEffects: true, StateDir: filepath.Join(t.TempDir(), "state")}
	s, err := New(cfg, dst)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if s != nil {
			_ = s.Close()
		}
	})
	exec(t, s, "check", Request{Bundle: effectsBundle})
	var staged struct {
		Revision string `json:"revision"`
	}
	if err := json.Unmarshal(exec(t, s, "stage", Request{Bundle: effectsBundle, IdempotencyKey: "effect-stage"}), &staged); err != nil {
		t.Fatal(err)
	}
	if dst.Policy().Revision() != initial {
		t.Fatal("check/stage changed live policy")
	}
	assertReplay := func(revision string) {
		t.Helper()
		var d policy.Decision
		// No live source is necessary for synthetic evaluation.
		if err := json.Unmarshal(exec(t, s, "evaluate", Request{Revision: revision, Event: policy.Event{ClientIP: "synthetic"}}), &d); err != nil {
			t.Fatal(err)
		}
		if d.Verdict != "deny" || len(d.Effects) != 0 {
			t.Fatalf("actionable replay: %+v", d)
		}
	}
	assertReplay(staged.Revision)
	exec(t, s, "activate", Request{Revision: staged.Revision, ExpectedRevision: initial, IdempotencyKey: "effect-activate"})
	assertReplay("")
	if d, err := dst.Policy().Evaluate(policy.Event{ClientIP: "192.0.2.5"}); err != nil || len(d.Effects) != 1 {
		t.Fatalf("live admitted policy lost effects: %+v %v", d, err)
	}
	exec(t, s, "rollback", Request{ExpectedRevision: staged.Revision, IdempotencyKey: "effect-rollback"})
	assertReplay(staged.Revision)
	exec(t, s, "activate", Request{Revision: staged.Revision, ExpectedRevision: initial, IdempotencyKey: "effect-reactivate"})
	_ = s.Close()
	deniedCfg := cfg
	deniedCfg.AllowEffects = false
	if unexpected, err := New(deniedCfg, target(t)); err == nil {
		_ = unexpected.Close()
		t.Fatal("recovery bypassed effects admission")
	}
	restored := target(t)
	s, err = New(cfg, restored)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Policy().Revision() != staged.Revision {
		t.Fatal("admitted effect revision not restored")
	}
	assertReplay("")
	if _, _, err := s.compileBundle(restored.Policy()); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	// Read-only services may inspect admitted file policies, but never dispatch.
	s, err = New(Config{Token: "secret", AllowEffects: true}, restored)
	if err != nil {
		t.Fatal(err)
	}
	assertReplay("")
}
