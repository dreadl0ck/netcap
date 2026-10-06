package behavior

import (
	"testing"
	"time"
)

func TestTopologySeparatesOverlappingNetworksAndRoutedHosts(t *testing.T) {
	e, _ := testEngine(t, 100)
	edge := testFact()
	other := edge
	other.Scope.VLANs = []uint16{20}
	binding := Fact{Scope: edge.Scope, Kind: "binding", SrcIP: edge.SrcIP, MAC: "00:11:22:33:44:55", Provenance: "arp"}
	if err := e.Observe(testTime, edge, other, binding); err != nil {
		t.Fatal(err)
	}
	if err := e.Observe(testTime.Add(time.Second), edge); err != nil {
		t.Fatal(err)
	}
	graph := BuildTopology(e.Snapshot(), 100, "")
	if len(graph.Nodes) != 5 {
		t.Fatalf("overlapping host identities merged: %+v", graph.Nodes)
	}
	devices := 0
	for _, node := range graph.Nodes {
		if node.Kind == "device" {
			devices++
		}
	}
	if devices != 1 {
		t.Fatal("routed endpoints were assigned a shared next-hop device")
	}
	filtered := BuildTopology(e.Snapshot(), 100, scopeKey(other.Scope))
	if len(filtered.Nodes) != 2 || len(filtered.Links) != 1 {
		t.Fatal("topology scope filter leaked another VLAN")
	}
	capped := BuildTopology(e.Snapshot(), 2, "")
	if len(capped.Nodes) != 2 || !capped.Truncated || capped.TotalNodes != 5 {
		t.Fatal("graph limit silently lost coverage")
	}
}
