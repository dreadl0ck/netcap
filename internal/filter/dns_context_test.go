package filter

import (
	"github.com/dreadl0ck/netcap/types"
	"testing"
)

func TestDNSResolutionRuleUsesObservationSnapshot(t *testing.T) {
	program, err := CompileExpression(`DNSResolutionMatches(DNSResolutionState, DNSResolvedName, DNSResolvedAt, TimestampFirst, "Example.Test.", 1000)`, types.Type_NC_Connection)
	if err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{"resolved", "unobserved", "disabled"} {
		record := &types.Connection{TimestampFirst: 101, DNSResolvedAt: 100, DNSResolvedName: "example.test", DNSResolutionState: state}
		matched, err := EvaluateExpression(program, record)
		if err != nil || matched != (state == "resolved") {
			t.Fatalf("%s: matched=%v err=%v", state, matched, err)
		}
	}
	if DNSResolutionMatches("resolved", "example.test", -1<<63, 1<<63-1, "example.test", 1) {
		t.Fatal("age overflow matched")
	}
}
