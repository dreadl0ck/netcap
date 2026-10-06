package behavior

import (
	"fmt"
	"reflect"
	"testing"
)

func TestAssetContextScopeDirectionLabelsAndBounds(t *testing.T) {
	scope := Scope{Sensor: "fixture", Interface: "eth0", VLANs: []uint16{10}}
	other := scope
	other.VLANs = []uint16{20}
	state := Snapshot{Observed: map[string]Observation{}, Labels: map[string]AssetLabel{}, Corrections: map[string]Fact{}}
	add := func(fact Fact) string {
		id := factID(fact)
		state.Observed[id] = Observation{Fact: fact, FirstSeen: 1, LastSeen: 2, Samples: 2}
		return id
	}
	add(Fact{Scope: scope, Kind: "prefix", Value: "192.0.2.0/24", Provenance: "configured"})
	add(Fact{Scope: scope, Kind: "prefix", Value: "2001:db8::/64", Provenance: "router-advertisement"})
	add(Fact{Scope: other, Kind: "prefix", Value: "2001:db8::/64", Provenance: "router-advertisement"})
	mac := "00:11:22:33:44:55"
	labelID := add(Fact{Scope: scope, Kind: "binding", SrcIP: "192.0.2.1", MAC: mac, Provenance: "arp"})
	state.Labels[labelID] = AssetLabel{Fact: state.Observed[labelID].Fact, Name: "Office gateway", Role: "router"}
	service := add(Fact{Scope: scope, Kind: "service", SrcIP: "192.0.2.1", DstIP: "8.8.8.8", Protocol: "tcp", Port: 443})
	wrongScope := add(Fact{Scope: other, Kind: "service", SrcIP: "192.0.2.1", DstIP: "192.0.2.2", Protocol: "tcp", Port: 22})
	add(Fact{Scope: scope, Kind: "edge", SrcIP: "192.0.2.10", DstIP: "192.0.2.20"})
	before := len(state.Observed)
	context, err := BuildAssetContext(state, mac)
	if err != nil || context.TotalRecords != 2 {
		t.Fatalf("MAC joins: %+v, %v", context, err)
	}
	for _, row := range context.Records {
		if row.ID == wrongScope {
			t.Fatal("cross-VLAN association")
		}
		if row.ID == service && (row.Direction != "outbound" || len(row.Prefixes) != 2) {
			t.Fatalf("prefix direction: %+v", row)
		}
		if row.ID == labelID && (row.Label == nil || row.Label.Name != "Office gateway") {
			t.Fatal("asset label omitted")
		}
	}
	context, err = BuildAssetContext(state, "192.0.2.1")
	if err != nil || context.TotalRecords != 3 {
		t.Fatalf("exact IP match: %+v, %v", context, err)
	}
	for _, row := range context.Records {
		if row.ID == wrongScope && row.Direction != "unknown" {
			t.Fatal("invented prefix in overlapping VLAN")
		}
	}
	id := add(Fact{Scope: scope, Kind: "edge", SrcIP: "2001:db8::1", DstIP: "2001:db8::2"})
	v6, err := BuildAssetContext(state, "2001:db8::1")
	if err != nil || len(v6.Records) != 1 || v6.Records[0].ID != id || v6.Records[0].Direction != "internal" {
		t.Fatalf("IPv6 prefix: %+v, %v", v6, err)
	}
	if len(state.Observed) != before+1 || !reflect.DeepEqual(state.Labels[labelID].Name, "Office gateway") {
		t.Fatal("summary mutated observations")
	}
	for i := range 100 {
		add(Fact{Scope: scope, Kind: "edge", SrcIP: "192.0.2.1", DstIP: fmt.Sprintf("198.51.100.%d", i+1)})
	}
	bounded, err := BuildAssetContext(state, "192.0.2.1")
	if err != nil || len(bounded.Records) != 64 || !bounded.Truncated || bounded.TotalRecords != 103 {
		t.Fatalf("context bound: %+v, %v", bounded, err)
	}
	if _, err := BuildAssetContext(state, "not an address"); err == nil {
		t.Fatal("invalid asset accepted")
	}
}
