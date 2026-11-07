package firewall

import (
	"context"
	"testing"

	"github.com/dreadl0ck/netcap/internal/networkfirewall"
	"github.com/dreadl0ck/netcap/internal/policy"
)

func TestPacketPolicyAdapter(t *testing.T) {
	p, err := policy.Compile(policy.Bundle{Version: "1", ID: "network", Mode: "enforce", Default: "allow", Rules: []policy.Rule{{ID: "tls", Action: "deny", Expression: `Protocol == "network" && Network.SrcIP == "192.0.2.33" && Network.DstIP == "10.1.0.2" && Network.SrcPort == 1234 && Network.DstPort == 443 && Network.Transport == "tcp" && Network.IPVersion == 4 && Network.TCPFlags == 2 && Network.Direction == "inbound" && TLS.ServerName == "blocked.example" && TLS.ALPN == "h2,http/1.1" && TLS.Encrypted`}}})
	if err != nil {
		t.Fatal(err)
	}
	r := &runtimeEvaluator{ctx: context.Background()}
	r.SetPolicy(p)
	e := networkfirewall.PacketEvent{SrcIP: "192.0.2.33", DstIP: "10.1.0.2", SrcPort: 1234, DstPort: 443, Transport: "tcp", IPVersion: 4, TCPFlags: 2, Direction: "inbound", TLS: &networkfirewall.TLSMetadata{ServerName: "blocked.example", ALPN: []string{"h2", "http/1.1"}}}
	adapter := packetEvaluator{r}
	d, err := adapter.EvaluatePacket(e)
	if err != nil || d.Verdict != networkfirewall.Deny {
		t.Fatalf("packet metadata lost: %+v %v", d, err)
	}
	e.TLS = nil
	d, err = adapter.EvaluatePacket(e)
	if err != nil || d.Verdict != networkfirewall.Allow {
		t.Fatalf("absent TLS: %+v %v", d, err)
	}
}
