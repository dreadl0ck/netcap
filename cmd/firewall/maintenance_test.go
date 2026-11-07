package firewall

import (
	"context"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/policy"
)

func TestIdlePolicyMaintenanceUsesLatestRevisionAndJoins(t *testing.T) {
	compile := func(id string) *policy.Compiled {
		t.Helper()
		p, err := policy.Compile(policy.Bundle{Version: "1", ID: id, Mode: "enforce", Default: "allow", Rules: []policy.Rule{{ID: "threshold", Expression: "true", Action: "deny", Threshold: &policy.Threshold{Count: 2, Window: "1ms", GroupBy: "ClientIP"}}}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = p.Evaluate(policy.Event{ClientIP: "private-group"}); err != nil {
			t.Fatal(err)
		}
		if p.StateStats().Groups != 1 {
			t.Fatal("test did not create policy state")
		}
		return p
	}
	first, latest := compile("first"), compile("latest")
	var current atomic.Pointer[policy.Compiled]
	current.Store(first)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	stop := startPolicyMaintenance(ctx, current.Load, io.Discard)
	defer stop()
	current.Store(latest)
	deadline := time.Now().Add(12 * time.Second)
	for latest.StateStats().Groups != 0 && time.Now().Before(deadline) {
		time.Sleep(25 * time.Millisecond)
	}
	if latest.StateStats().Groups != 0 {
		t.Fatal("idle 10-second maintenance did not expire latest policy state")
	}
	if first.StateStats().Groups != 1 {
		t.Fatal("maintenance pinned the superseded policy")
	}
	cancel()
	done := make(chan struct{})
	go func() { stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("idle maintenance did not join after cancellation")
	}
}
