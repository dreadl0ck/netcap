package rules

import (
	"testing"

	"github.com/dreadl0ck/netcap/internal/filter"
	"github.com/dreadl0ck/netcap/types"
)

func TestS7HuntUsesInitiatorForEachDirection(t *testing.T) {
	filter.SetApprovedWorkstations([]string{"192.0.2.10"})
	t.Cleanup(func() { filter.SetApprovedWorkstations(nil) })
	config, err := LoadRulesFromFile("examples/s7comm_hunt.yml")
	if err != nil {
		t.Fatal(err)
	}
	if err := CompileRules(config); err != nil {
		t.Fatal(err)
	}
	rules := map[string]*Rule{}
	for _, rule := range config.Rules {
		rules[rule.Name] = rule
	}
	for _, test := range []struct {
		name, rule, src, dst string
		message, errorCode   int32
		want                 bool
	}{
		{"approved request", "S7comm Write Operation", "192.0.2.10", "192.0.2.20", 1, 0, false},
		{"unapproved request", "S7comm Write Operation", "192.0.2.11", "192.0.2.20", 1, 0, true},
		{"reply is not a request", "S7comm Write Operation", "192.0.2.20", "192.0.2.10", 3, 0, false},
		{"approved response destination", "S7comm Critical Operation Acknowledgment", "192.0.2.20", "192.0.2.10", 3, 0, false},
		{"unapproved response destination", "S7comm Critical Operation Acknowledgment", "192.0.2.20", "192.0.2.11", 3, 0, true},
		{"header error", "S7comm Critical Operation Acknowledgment", "192.0.2.20", "192.0.2.11", 3, 1, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			record := &types.S7Comm{Timestamp: 1700000000000000000, ProtocolId: 50, MessageType: test.message, FunctionCode: 5, IsCriticalOperation: true, SrcIP: test.src, DstIP: test.dst, ErrorCode: test.errorCode}
			alert, err := EvaluateRule(rules[test.rule], record)
			if err != nil {
				t.Fatal(err)
			}
			if (alert != nil) != test.want {
				t.Fatalf("alert = %v, want match %v", alert, test.want)
			}
		})
	}
}
