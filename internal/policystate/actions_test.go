package policystate

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/dreadl0ck/netcap/internal/policy"
)

func TestTypedEffectsAuthorityAndClientValidation(t *testing.T) {
	cfg := config(t)
	cfg.AllowEffects = true
	s := store(t, cfg)
	server := httptest.NewServer(s.Handler())
	defer server.Close()
	c := client(t, server.URL, testToken)
	e := policy.Event{Protocol: "network", ClientIP: "192.0.2.5", Network: policy.NetworkEvent{SrcIP: "192.0.2.5", DstIP: "198.51.100.1", Transport: "tcp", SrcPort: 12345, DstPort: 443}}
	for _, kind := range []string{"block_source", "quarantine", "rate_source", "redirect_source", "notify", "drop_flow", "reject_flow"} {
		t.Run(kind, func(t *testing.T) {
			profile := ""
			if kind == "quarantine" || kind == "rate_source" || kind == "redirect_source" {
				profile = "operator"
			}
			b := policy.Bundle{Version: "1", ID: "typed", Mode: "enforce", Default: "allow", Rules: []policy.Rule{{ID: "action", Action: "deny", Expression: "true", Effects: []policy.Effect{{Kind: kind, Profile: profile, Target: "source", Scope: "edge", Duration: "10s"}}}}}
			p, err := policy.CompileWithOptions(b, policy.CompileOptions{AllowEffects: true})
			if err != nil {
				t.Fatal(err)
			}
			d, err := c.Evaluate(context.Background(), p, e)
			if err != nil || len(d.Effects) != 1 {
				t.Fatalf("authority round trip: %+v %v", d, err)
			}
			for _, mutate := range []func(*policy.Intent){
				func(i *policy.Intent) { i.Profile = "other" },
				func(i *policy.Intent) { i.Flow.SourcePort++ },
				func(i *policy.Intent) { i.Kind = "shell" },
			} {
				bad := d
				bad.Effects = append([]policy.Intent(nil), d.Effects...)
				mutate(&bad.Effects[0])
				bad.Effects[0].ID = policy.IntentID(bad.Effects[0])
				if validateDecision(p, e, bad) == nil {
					t.Fatal("accepted substituted action with recomputed identity")
				}
			}
			raw := request(p, e)
			// Submit raw unsupported enums directly to the authority, bypassing client compilation.
			raw.Bundle = []byte(`{"version":"1","id":"bad","mode":"enforce","default":"allow","rules":[{"id":"action","action":"deny","expression":"true","effects":[{"kind":"shell","target":"source","scope":"edge","duration":"10s"}]}]}`)
			if _, err := s.Evaluate(context.Background(), testScope, raw); err == nil {
				t.Fatal("authority accepted unsupported action enum")
			}
		})
	}
}
