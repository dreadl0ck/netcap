package rules

import (
	"fmt"
	"math"
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

func BenchmarkThresholdWindowPruning(b *testing.B) {
	engine := &Engine{thresholdTrackers: make(map[string]*thresholdTracker)}
	rule := &Rule{Name: "fixture", Threshold: 1024, ThresholdWindow: 60}
	record := &types.HTTP{Timestamp: time.Second.Nanoseconds()}
	b.ReportAllocs()
	for b.Loop() {
		for i := range rule.Threshold {
			if engine.checkThreshold(rule, record) != (i == rule.Threshold-1) {
				b.Fatal("threshold did not trigger and rearm at the expected count")
			}
		}
	}
}

func TestThresholdWindowKeepsOnlyEligibleMatches(t *testing.T) {
	engine := &Engine{thresholdTrackers: make(map[string]*thresholdTracker)}
	rule := &Rule{Name: "fixture", Threshold: 4, ThresholdWindow: 2}
	for _, step := range []struct {
		seconds int64
		trigger bool
	}{
		{1, false}, {2, false}, {3, false}, {4, false}, // 1 expired; 2 is on the boundary.
		{3, false}, {4, true}, // The earlier 4 was discarded when time went backward.
		{4, false}, // Rearmed.
	} {
		if got := engine.checkThreshold(rule, &types.HTTP{Timestamp: step.seconds * int64(time.Second)}); got != step.trigger {
			t.Fatalf("timestamp %d: trigger=%t, want %t", step.seconds, got, step.trigger)
		}
	}
}

func TestAuditReplayUsesRecordTimeForDedupAndRateWindows(t *testing.T) {
	t.Run("modern", func(t *testing.T) { testAuditReplayClock(t, time.Unix(1700000000, 0)) })
	t.Run("before-epoch", func(t *testing.T) { testAuditReplayClock(t, time.Unix(-3600, 0)) })
}

func TestAuditReplayThresholdUsesSignedRecordTime(t *testing.T) {
	config := &Config{Rules: []*Rule{{Name: "fixture", Type: "HTTP", Expression: `Method == "GET"`, Enabled: true, Threshold: 2, ThresholdWindow: 60}}}
	replay, err := NewAuditReplay(config, new(MockAlertWriter))
	if err != nil {
		t.Fatal(err)
	}
	for i, seconds := range []int64{-120, -130, -125} {
		got, err := replay.Evaluate(&types.HTTP{Method: "GET", Timestamp: time.Unix(seconds, 0).UnixNano()})
		want := []int{0, 0, 1}[i]
		if err != nil || got != want {
			t.Fatalf("timestamp %d: got %d alerts, want %d: %v", seconds, got, want, err)
		}
	}
}

func TestAuditReplayThresholdRejectsTimestampDeltaOverflow(t *testing.T) {
	config := &Config{Rules: []*Rule{{Name: "fixture", Type: "HTTP", Expression: `Method == "GET"`, Enabled: true, Threshold: 2, ThresholdWindow: 60}}}
	replay, err := NewAuditReplay(config, new(MockAlertWriter))
	if err != nil {
		t.Fatal(err)
	}
	for i, ts := range []int64{math.MinInt64 + 1, math.MaxInt64 - 1, math.MaxInt64} {
		got, err := replay.Evaluate(&types.HTTP{Method: "GET", Timestamp: ts})
		want := [3]int{0, 0, 1}[i]
		if err != nil || got != want {
			t.Fatalf("timestamp %d: got %d alerts, want %d: %v", ts, got, want, err)
		}
	}
}

func TestAuditReplayDedupRejectsTimestampDeltaOverflow(t *testing.T) {
	config := &Config{Rules: []*Rule{{Name: "fixture", Type: "HTTP", Expression: `Method == "GET"`, Enabled: true}}}
	replay, err := NewAuditReplay(config, new(MockAlertWriter))
	if err != nil {
		t.Fatal(err)
	}
	for i, ts := range []int64{math.MinInt64 + 1, math.MaxInt64 - 1, math.MaxInt64} {
		got, err := replay.Evaluate(&types.HTTP{Method: "GET", Timestamp: ts, SrcIP: "192.0.2.1"})
		want := [3]int{1, 1, 0}[i]
		if err != nil || got != want {
			t.Fatalf("timestamp %d: got %d alerts, want %d: %v", ts, got, want, err)
		}
	}
}

func TestAuditReplayDistinctWindowRejectsTimestampDeltaOverflow(t *testing.T) {
	config := &Config{Rules: []*Rule{{Name: "fixture", Type: "HTTP", Expression: `Method == "GET"`, Enabled: true, DistinctField: "URL", DistinctThreshold: 2, ThresholdWindow: 60}}}
	replay, err := NewAuditReplay(config, new(MockAlertWriter))
	if err != nil {
		t.Fatal(err)
	}
	for i, ts := range []int64{math.MinInt64 + 1, math.MaxInt64 - 1, math.MaxInt64} {
		got, err := replay.Evaluate(&types.HTTP{Method: "GET", Timestamp: ts, SrcIP: "192.0.2.1", URL: fmt.Sprintf("/fixture/%d", i)})
		want := [3]int{0, 0, 1}[i]
		if err != nil || got != want {
			t.Fatalf("timestamp %d: got %d alerts, want %d: %v", ts, got, want, err)
		}
	}
}

func TestAuditReplaySequenceUsesFullTimestampRange(t *testing.T) {
	config := &Config{Rules: []*Rule{{
		Name: "fixture", Type: "HTTP", Expression: `Method == "POST"`, Enabled: true,
		Sequence: &Sequence{After: `Method == "GET"`, GroupBy: []string{"SrcIP"}, Within: 60},
	}}}
	for _, tc := range []struct {
		name        string
		read, write int64
		want        int
	}{
		{"valid before epoch", -2, -1, 1},
		{"expired across epoch", math.MinInt64 + 1, math.MaxInt64, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			replay, err := NewAuditReplay(config, new(MockAlertWriter))
			if err != nil {
				t.Fatal(err)
			}
			if n, err := replay.Evaluate(&types.HTTP{Method: "GET", SrcIP: "192.0.2.1", Timestamp: tc.read}); n != 0 || err != nil {
				t.Fatalf("sequence start: alerts=%d err=%v", n, err)
			}
			if n, err := replay.Evaluate(&types.HTTP{Method: "POST", SrcIP: "192.0.2.1", Timestamp: tc.write}); n != tc.want || err != nil {
				t.Fatalf("alerts=%d, want %d: %v", n, tc.want, err)
			}
		})
	}
}

func testAuditReplayClock(t *testing.T, base time.Time) {
	t.Helper()
	config := &Config{Rules: []*Rule{{Name: "fixture", Type: "HTTP", Expression: `Method == "GET"`, Enabled: true}}}
	var prior []*types.Alert
	for range 2 {
		writer := new(MockAlertWriter)
		replay, err := NewAuditReplay(config, writer)
		if err != nil {
			t.Fatal(err)
		}
		replay.engine.SetRateLimit(1)
		for _, step := range []struct {
			src  string
			ts   int64
			want int
		}{
			{"192.0.2.1", base.UnixNano(), 1},
			{"192.0.2.2", base.Add(time.Second).UnixNano(), 0},
			{"192.0.2.3", base.Add(time.Minute).UnixNano(), 1},
			{"192.0.2.4", base.UnixNano(), 0},
			{"192.0.2.5", 0, 0},
			{"192.0.2.1", base.Add(6 * time.Minute).UnixNano(), 1},
		} {
			got, err := replay.Evaluate(&types.HTTP{Method: "GET", Timestamp: step.ts, SrcIP: step.src})
			if err != nil || got != step.want {
				t.Fatalf("%+v: %d %v", step, got, err)
			}
		}
		for _, alert := range writer.alerts {
			alert.DetectedAt = 0
		}
		if prior != nil && !reflect.DeepEqual(writer.alerts, prior) {
			t.Fatal("identical audit order produced different alerts")
		}
		prior = writer.alerts
	}
}
