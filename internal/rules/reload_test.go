package rules

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/types"
)

func reloadConfig(expression string, threshold int) *Config {
	return &Config{Rules: []*Rule{{Name: "reload", Type: "TCP", Expression: expression, Enabled: true, Threshold: threshold, ThresholdWindow: 60}}}
}

func TestReloadDoesNotInheritThresholdOrSuppressionState(t *testing.T) {
	var written atomic.Int32
	engine, err := NewEngineFromConfig(reloadConfig("DstPort == 443", 2), alertWriterFunc(func(*types.Alert) error { written.Add(1); return nil }))
	if err != nil {
		t.Fatal(err)
	}
	record := &types.TCP{Timestamp: time.Now().UnixNano(), SrcIP: "192.0.2.1", DstIP: "198.51.100.1", DstPort: 443}
	if count, err := engine.Evaluate(record); err != nil || count != 0 {
		t.Fatalf("initial match: %d %v", count, err)
	}
	if err := engine.UpdateConfig(reloadConfig("DstPort == 8443", 2)); err != nil {
		t.Fatal(err)
	}
	record.DstPort = 8443
	if count, err := engine.Evaluate(record); err != nil || count != 0 {
		t.Fatalf("old threshold evidence leaked into new rule: %d %v", count, err)
	}
	if count, err := engine.Evaluate(record); err != nil || count != 1 {
		t.Fatalf("new threshold did not trigger: %d %v", count, err)
	}
	engine.SetRateLimit(1)
	if err := engine.UpdateConfig(reloadConfig("DstPort > 0", 1)); err != nil {
		t.Fatal(err)
	}
	if count, err := engine.Evaluate(record); err != nil || count != 1 {
		t.Fatalf("old dedup/rate suppression leaked: %d %v", count, err)
	}
	if written.Load() != 2 {
		t.Fatal("previous alerts were lost or duplicated")
	}
	if stats := engine.GetStats(); stats["config_generation"] != uint64(3) || stats["reload_state_policy"] != "reset-on-reload" {
		t.Fatal(stats)
	}
}

func TestRejectedReloadPreservesCurrentConfigurationAndPendingEvidence(t *testing.T) {
	engine, err := NewEngineFromConfig(reloadConfig("DstPort == 443", 2), alertWriterFunc(func(*types.Alert) error { return nil }))
	if err != nil {
		t.Fatal(err)
	}
	record := &types.TCP{Timestamp: time.Now().UnixNano(), SrcIP: "192.0.2.1", DstIP: "198.51.100.1", DstPort: 443}
	if _, err := engine.Evaluate(record); err != nil {
		t.Fatal(err)
	}
	if err := engine.UpdateConfig(reloadConfig("not valid expr (", 2)); err == nil {
		t.Fatal("invalid reload accepted")
	}
	if count, err := engine.Evaluate(record); err != nil || count != 1 {
		t.Fatalf("failed reload changed active state: %d %v", count, err)
	}
	if engine.GetStats()["config_generation"] != uint64(1) {
		t.Fatal("failed reload advanced generation")
	}
}

func TestReloadDropsSequenceAntecedentsAndDistinctEvidence(t *testing.T) {
	t.Run("sequence", func(t *testing.T) {
		engine, _ := sequenceEngine(t, &Sequence{After: "FunctionCode == 3", GroupBy: []string{"SrcIP", "DstIP"}, Within: 60}, "FunctionCode == 6")
		if _, err := engine.Evaluate(modbusAt(0, "request", 3, 40)); err != nil {
			t.Fatal(err)
		}
		if err := engine.UpdateConfig(engine.config); err != nil {
			t.Fatal(err)
		}
		if count, err := engine.Evaluate(modbusAt(1, "request", 6, 40)); err != nil || count != 0 {
			t.Fatalf("old antecedent survived reload: %d %v", count, err)
		}
	})
	t.Run("distinct", func(t *testing.T) {
		configuration := reloadConfig("DstPort > 0", 1)
		configuration.Rules[0].DistinctField, configuration.Rules[0].DistinctThreshold = "DstPort", 2
		engine, err := NewEngineFromConfig(configuration, alertWriterFunc(func(*types.Alert) error { return nil }))
		if err != nil {
			t.Fatal(err)
		}
		record := &types.TCP{Timestamp: time.Now().UnixNano(), SrcIP: "192.0.2.1", DstIP: "198.51.100.1", DstPort: 443}
		if _, err := engine.Evaluate(record); err != nil {
			t.Fatal(err)
		}
		if err := engine.UpdateConfig(configuration); err != nil {
			t.Fatal(err)
		}
		record.DstPort = 8443
		if count, err := engine.Evaluate(record); err != nil || count != 0 {
			t.Fatalf("old distinct observation survived reload: %d %v", count, err)
		}
	})
}

func TestReloadOwnsConfigurationAndSerializesWithConcurrentEvaluation(t *testing.T) {
	configuration := reloadConfig("DstPort == 443", 1)
	engine, err := NewEngineFromConfig(configuration, alertWriterFunc(func(*types.Alert) error { return nil }))
	if err != nil {
		t.Fatal(err)
	}
	configuration.Rules[0].Enabled = false
	record := &types.TCP{Timestamp: time.Now().UnixNano(), SrcIP: "192.0.2.1", DstIP: "198.51.100.1", DstPort: 443}
	if count, err := engine.Evaluate(record); err != nil || count != 1 {
		t.Fatalf("caller mutated active configuration: %d %v", count, err)
	}
	var workers sync.WaitGroup
	for range 4 {
		workers.Go(func() {
			for range 50 {
				if _, err := engine.Evaluate(record); err != nil {
					t.Error(err)
				}
				_ = engine.GetStats()
			}
		})
	}
	for range 20 {
		engine.SetPerformanceTracker(nil)
		engine.SetFirewallManager(nil)
		engine.SetRateLimit(100)
		configuration := reloadConfig("DstPort == 443", 2)
		if err := engine.UpdateConfig(configuration); err != nil {
			t.Fatal(err)
		}
		configuration.Rules[0].Expression = "invalid after publication"
	}
	workers.Wait()
}
