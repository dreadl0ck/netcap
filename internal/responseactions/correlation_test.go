package responseactions

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/dreadl0ck/netcap/internal/policy"
)

func TestCrossProtocolDistinctSequenceDispatchesOnlyAfterCompletion(t *testing.T) {
	c, backend := controller(t, true)
	server := httptest.NewTLSServer(c.Handler())
	defer server.Close()
	b := newBroker(t, configFor(t, server))
	r := policy.Rule{ID: "correlate", Action: "deny", Sequence: &policy.Sequence{
		Name: "dns-tls-network", Window: "1m", GroupByFields: []string{"Attributes.tenant", "ClientIP"}, Steps: []string{
			`Protocol == "dns" && DNS.Name == "command.example"`,
			`Protocol == "tls" && TLS.JA4 == "suspicious"`,
			`Protocol == "network" && Network.DstPort == 443`,
		}}, Threshold: &policy.Threshold{Count: 2, Mode: "sliding", Window: "1m", Distinct: "Attributes.vector", GroupByFields: []string{"Attributes.tenant", "ClientIP"}},
		Effects: []policy.Effect{{Kind: "block_source", Duration: "1m", Target: "source", Scope: "edge"}},
	}
	p, err := policy.CompileWithOptions(policy.Bundle{Version: "1", ID: "cross-protocol", Mode: "enforce", Default: "allow", Rules: []policy.Rule{r}}, policy.CompileOptions{AllowEffects: true})
	if err != nil {
		t.Fatal(err)
	}
	wrapper := &Evaluator{Policy: p, Broker: b, Source: func(e policy.Event, target string) (string, bool) { return e.Network.SrcIP, target == "source" }}
	var events []policy.Event
	for _, vector := range []string{"a", "b"} {
		for _, protocol := range []string{"dns", "tls", "network"} {
			events = append(events, policy.Event{Protocol: protocol, ClientIP: "192.0.2.5", Network: policy.NetworkEvent{SrcIP: "192.0.2.5", DstPort: 443}, DNS: policy.DNSEvent{Name: "command.example"}, TLS: policy.TLSEvent{JA4: "suspicious"}, Attributes: map[string]string{"tenant": "one", "vector": vector}})
		}
	}
	replay, err := p.Simulate(events)
	if err != nil {
		t.Fatal(err)
	}
	for i, d := range replay {
		if len(d.Effects) != 0 {
			t.Fatal("synthetic cross-protocol replay emitted effects")
		}
		want := "allow"
		if i == len(replay)-1 {
			want = "deny"
		}
		if d.Verdict != want {
			t.Fatal("replay completion mismatch", i, d)
		}
	}
	var final policy.Decision
	for i, e := range events {
		d, err := wrapper.Evaluate(e)
		if err != nil {
			t.Fatal(err)
		}
		if i < len(events)-1 {
			if d.Verdict != "allow" || len(d.Effects) != 0 || len(b.Receipts()) != 0 {
				t.Fatal("incomplete sequence/distinct gate dispatched", i, d)
			}
		} else {
			final = d
		}
	}
	if final.Verdict != "deny" || len(final.Effects) != 1 {
		t.Fatal(final)
	}
	await(t, b, final.Effects[0].ID, "applied")
	leases, err := backend.List(context.Background())
	if err != nil || len(leases) != 1 || !leases[0].ExpiresAt.Equal(final.Effects[0].ExpiresAt) {
		t.Fatalf("correlation lease deadline: %+v %v", leases, err)
	}
}
