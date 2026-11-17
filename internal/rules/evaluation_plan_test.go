package rules

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/types"
)

func TestSharedEvaluationPreservesAlertProvenanceAndClockGates(t *testing.T) {
	config := &Config{Rules: []*Rule{
		{Name: "ordinary", Type: "HTTP", Expression: `Method == "GET"`, Enabled: true},
		{Name: "threshold", Type: "HTTP", Expression: `Method == "GET"`, Enabled: true, Threshold: 2},
	}}
	writer := new(MockAlertWriter)
	engine, err := NewEngineFromConfig(config, writer)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1700000000, 0)
	engine.clock = func() time.Time { return now }
	engine.SetDeduplicationWindow(0)
	engine.SetRateLimit(2)
	record := &types.HTTP{Method: "GET", URL: "/control", Timestamp: now.UnixNano()}
	for range 6 {
		if _, err := engine.Evaluate(record); err != nil {
			t.Fatal(err)
		}
	}
	counts := map[string]int{}
	for _, alert := range writer.alerts {
		counts[alert.RuleName]++
		for _, rule := range engine.config.Rules {
			if rule.Name != alert.RuleName {
				continue
			}
			want, err := EvaluateRule(rule, record)
			if err != nil {
				t.Fatal(err)
			}
			want.DetectedAt = alert.DetectedAt
			if !reflect.DeepEqual(want, alert) {
				t.Fatal("shared evaluation changed alert provenance", want, alert)
			}
		}
	}
	if counts["ordinary"] != 2 || counts["threshold"] != 2 {
		t.Fatal("clock-controlled gates changed", counts)
	}
	now = now.Add(61 * time.Second)
	if count, err := engine.Evaluate(record); err != nil || count != 1 {
		t.Fatal("rate window did not advance", count, err)
	}
}

func BenchmarkSharedRuleEvaluation(b *testing.B) {
	for _, n := range []int{1, 32, 128} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			config := &Config{}
			for i := range n {
				config.Rules = append(config.Rules, &Rule{Name: fmt.Sprint(i), Type: "HTTP", Expression: `Method == "POST"`, Enabled: true})
			}
			engine, err := NewEngineFromConfig(config, new(MockAlertWriter))
			if err != nil {
				b.Fatal(err)
			}
			record := &types.HTTP{Method: "GET", URL: "/control", ResponseHeader: map[string]string{"Content-Type": "text/plain"}}
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if _, err := engine.Evaluate(record); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
