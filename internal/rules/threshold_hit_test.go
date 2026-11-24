package rules

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/types"
)

// A distinct-count alert used to carry only the record that crossed the
// threshold: C2 List Walk fired 3 alerts for 19 C2 IPs and showed 3.
func TestThresholdAlertsCarryWhatTheyCounted(t *testing.T) {
	var alerts []*types.Alert
	config := &Config{Rules: []*Rule{
		{Name: "walk", Type: "TCP", Expression: "SYN", Severity: "medium", Enabled: true, DistinctField: "DstIP", DistinctThreshold: 5, ThresholdWindow: 300},
		{Name: "brute", Type: "TCP", Expression: "SYN && DstPort == 22", Severity: "high", Enabled: true, Threshold: 3, ThresholdWindow: 60, GroupBy: []string{"SrcIP", "DstIP"}},
	}}
	replay, err := NewAuditReplay(config, alertWriterFunc(func(a *types.Alert) error { alerts = append(alerts, a); return nil }))
	if err != nil {
		t.Fatal(err)
	}
	base := int64(1_700_000_000) * int64(time.Second)
	for i := range 5 {
		if _, err := replay.Evaluate(&types.TCP{Timestamp: base + int64(i)*int64(time.Second), SrcIP: "10.0.0.5", DstIP: fmt.Sprintf("198.51.100.%d", i+1), DstPort: 8080, SYN: true}); err != nil {
			t.Fatal(err)
		}
	}
	for i := range 3 {
		if _, err := replay.Evaluate(&types.TCP{Timestamp: base + int64(10+i)*int64(time.Second), SrcIP: "10.0.0.6", DstIP: "192.0.2.22", DstPort: 22, SYN: true}); err != nil {
			t.Fatal(err)
		}
	}
	byRule := map[string]*types.Alert{}
	for _, a := range alerts {
		byRule[a.RuleName] = a
	}
	walk := byRule["walk"]
	if walk == nil || walk.Count != 5 || len(walk.Examples) != 5 || walk.FirstSeen != base || walk.LastSeen != base+4*int64(time.Second) {
		t.Fatalf("distinct evidence: %+v", walk)
	}
	var first map[string]string
	if err := json.Unmarshal([]byte(walk.Examples[0]), &first); err != nil || first["DstIP"] != "198.51.100.1" {
		t.Fatalf("first value %v %v", walk.Examples[0], err)
	}
	brute := byRule["brute"]
	var key struct {
		Rule  string
		Group map[string]string
	}
	if brute == nil || brute.Count != 3 || json.Unmarshal([]byte(brute.AggregateKey), &key) != nil || key.Group["SrcIP"] != "10.0.0.6" || key.Group["DstIP"] != "192.0.2.22" {
		t.Fatalf("grouped evidence: %+v", brute)
	}
}

func TestDistinctHitCapsValues(t *testing.T) {
	values := map[string]int64{}
	for i := range maxThresholdValues + 10 {
		values[fmt.Sprint(i)] = int64(i)
	}
	hit := distinctHit("src", values)
	alert := &types.Alert{}
	hit.annotate(&Rule{Name: "r", DistinctField: "DstIP"}, alert)
	if alert.Count != uint64(maxThresholdValues+10) || len(alert.Examples) != maxThresholdValues+1 {
		t.Fatalf("count %d examples %d", alert.Count, len(alert.Examples))
	}
}
