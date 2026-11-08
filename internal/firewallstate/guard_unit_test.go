package firewallstate

import (
	"context"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/policy"
)

func guardPolicy(t *testing.T, id string) *policy.Compiled {
	t.Helper()
	c, err := policy.Compile(policy.Bundle{Version: "1", ID: id, Mode: "enforce", Default: "allow"})
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func guardForUnit(t *testing.T, s *Service, id, unit string) *Guard {
	t.Helper()
	g, err := NewGuardWithStore(GuardConfig{ID: id, Unit: unit, Limit: 1, Window: time.Hour}, s.Bind(testScope))
	if err != nil {
		t.Fatal(err)
	}
	return g
}
func inspectionEvent(kind, protocol, phase string) policy.Event {
	return policy.Event{Protocol: protocol, Phase: phase, Attributes: map[string]string{"inspection.kind": kind}}
}
func guardDecision(t *testing.T, g *Guard, c *policy.Compiled, e policy.Event, status int) {
	t.Helper()
	d, err := g.Evaluate(context.Background(), c, e)
	if err != nil || d.Status != status {
		t.Fatalf("unit=%s kind=%q phase=%q: %+v %v, want status %d", g.cfg.Unit, e.Attributes["inspection.kind"], e.Phase, d, err, status)
	}
}

func TestGuardRequestUnitCountsHeadersOnce(t *testing.T) {
	s, err := New(stateConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c := guardPolicy(t, "request-policy")
	g := guardForUnit(t, s, "limit", "")
	guardDecision(t, g, c, inspectionEvent("headers", "grpc", "request"), 0)
	for _, e := range []policy.Event{inspectionEvent("message", "grpc", "request"), inspectionEvent("message", "websocket", "request"), inspectionEvent("trailers", "grpc", "request"), inspectionEvent("headers", "grpc", "response"), inspectionEvent("message", "grpc", "response")} {
		guardDecision(t, g, c, e, 0)
	}
	guardDecision(t, g, c, inspectionEvent("headers", "grpc", "request"), 429)
	legacy := guardForUnit(t, s, "legacy", "")
	guardDecision(t, legacy, c, policy.Event{}, 0)
	guardDecision(t, legacy, c, policy.Event{Attributes: map[string]string{"other": "value"}}, 429)
}

func TestGuardMessageUnitCountsOnlyRequestMessages(t *testing.T) {
	s, err := New(stateConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c := guardPolicy(t, "message-policy")
	g := guardForUnit(t, s, "limit", "message")
	for _, e := range []policy.Event{policy.Event{}, inspectionEvent("headers", "grpc", "request"), inspectionEvent("trailers", "grpc", "request"), inspectionEvent("message", "grpc", "response")} {
		guardDecision(t, g, c, e, 0)
	}
	if ready, _ := g.Ready(); ready {
		t.Fatal("skipped events fabricated shared-state contact")
	}
	guardDecision(t, g, c, inspectionEvent("message", "websocket", "request"), 0)
	guardDecision(t, g, c, inspectionEvent("message", "grpc", "request"), 429)
}

func TestGuardUnitIDAndRevisionIsolation(t *testing.T) {
	s, err := New(stateConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c := guardPolicy(t, "first")
	headers := inspectionEvent("headers", "grpc", "request")
	message := inspectionEvent("message", "grpc", "request")
	request := guardForUnit(t, s, "same", "request")
	messages := guardForUnit(t, s, "same", "message")
	guardDecision(t, request, c, headers, 0)
	guardDecision(t, messages, c, message, 0)
	guardDecision(t, guardForUnit(t, s, "same", ""), c, headers, 429)
	guardDecision(t, guardForUnit(t, s, "other", "request"), c, headers, 0)
	guardDecision(t, request, guardPolicy(t, "second"), headers, 0)
}

func TestGuardSkippedUnitsStillRunNativePolicy(t *testing.T) {
	s, err := New(stateConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c, err := policy.Compile(policy.Bundle{Version: "1", ID: "deny-messages", Mode: "enforce", Default: "allow", Rules: []policy.Rule{{ID: "message", Expression: `Attributes["inspection.kind"] == "message"`, Action: "deny"}}})
	if err != nil {
		t.Fatal(err)
	}
	g := guardForUnit(t, s, "limit", "request")
	guardDecision(t, g, c, inspectionEvent("message", "grpc", "request"), 403)
	if _, err = NewGuardWithStore(GuardConfig{ID: "limit", Unit: "frame", Limit: 1, Window: time.Hour}, s.Bind(testScope)); err == nil {
		t.Fatal("unknown unit accepted")
	}
	d, err := g.Evaluate(context.Background(), c, inspectionEvent("unknown", "grpc", "request"))
	if err == nil || d.Verdict != "deny" {
		t.Fatal("unknown inspection.kind bypassed guard")
	}
}
