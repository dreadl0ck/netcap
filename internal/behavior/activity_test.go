package behavior

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func lateralFixture(t *testing.T, policy Policy, cap int) (*Engine, *testSink) {
	t.Helper()
	sink := &testSink{}
	e, err := Open(Config{Path: filepath.Join(t.TempDir(), "Behavior.json"), MinLearning: time.Second, MinSamples: 2, MaxFacts: cap, Policy: &policy}, sink)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Close() })
	if err := e.AddPrefix(testFact().Scope, "192.0.2.0/24", "configured"); err != nil {
		t.Fatal(err)
	}
	learn(t, e, testFact())
	return e, sink
}

func attempt(src, dst string, port uint16, token string) Fact {
	return Fact{Scope: testFact().Scope, Kind: "service", SrcIP: src, DstIP: dst, Protocol: "tcp", Port: port, Token: token}
}

func detectorCount(sink *testSink, name string) int {
	count := 0
	for _, alert := range sink.alerts {
		if alert.RuleName == name {
			count++
		}
	}
	return count
}

func TestSMBFanoutUsesDistinctInternalTargets(t *testing.T) {
	e, sink := lateralFixture(t, DefaultPolicy(), 100)
	for i := range 20 {
		if err := e.Observe(testTime.Add(time.Duration(i+2)*time.Second), attempt("192.0.2.1", "192.0.2.2", 445, fmt.Sprint(i))); err != nil {
			t.Fatal(err)
		}
	}
	if detectorCount(sink, "lateral.smb-fanout") != 0 {
		t.Fatal("repeated attempts to one host became fan-out")
	}
	for i := range 4 {
		if err := e.Observe(testTime.Add(time.Duration(i+22)*time.Second), attempt("192.0.2.1", fmt.Sprintf("192.0.2.%d", i+3), 445, fmt.Sprint(i))); err != nil {
			t.Fatal(err)
		}
	}
	if detectorCount(sink, "lateral.smb-fanout") != 1 {
		t.Fatal("five distinct hosts were not detected")
	}
	for _, alert := range sink.alerts {
		if alert.RuleName == "lateral.smb-fanout" {
			var evidence Evidence
			if err := json.Unmarshal([]byte(alert.MatchedRecord), &evidence); err != nil {
				t.Fatal(err)
			}
			if evidence.Count != 5 || len(evidence.Related) == 0 || evidence.WindowNS != int64(time.Minute) || evidence.Version != 1 {
				t.Fatalf("evidence = %+v", evidence)
			}
		}
	}
	if err := e.Observe(testTime.Add(3*time.Minute), attempt("192.0.2.1", "192.0.2.9", 445, "late")); err != nil {
		t.Fatal(err)
	}
	if len(e.Snapshot().Activity) != 1 {
		t.Fatal("expired activity retained")
	}
}

func TestRDPRetransmissionsAndApprovedScanner(t *testing.T) {
	policy := DefaultPolicy()
	policy.RDPAttempts = 3
	e, sink := lateralFixture(t, policy, 100)
	fact := attempt("192.0.2.1", "192.0.2.2", 3389, "same-flow")
	for i := range 5 {
		if err := e.Observe(testTime.Add(time.Duration(i+2)*time.Second), fact); err != nil {
			t.Fatal(err)
		}
	}
	if detectorCount(sink, "lateral.rdp-attempts") != 0 {
		t.Fatal("SYN retransmissions counted as new attempts")
	}
	for i := range 2 {
		fact.Token = fmt.Sprint(i)
		if err := e.Observe(testTime.Add(time.Duration(i+7)*time.Second), fact); err != nil {
			t.Fatal(err)
		}
	}
	if detectorCount(sink, "lateral.rdp-attempts") != 1 {
		t.Fatal("three independent connection attempts not detected")
	}
	policy.ApprovedSources = []string{"192.0.2.1"}
	allowed, allowedSink := lateralFixture(t, policy, 100)
	for i := range 10 {
		if err := allowed.Observe(testTime.Add(time.Duration(i+2)*time.Second), attempt("192.0.2.1", fmt.Sprintf("192.0.2.%d", i+3), 445, fmt.Sprint(i))); err != nil {
			t.Fatal(err)
		}
	}
	if len(allowedSink.alerts) != 0 {
		t.Fatalf("approved scanner produced %d alerts", len(allowedSink.alerts))
	}
}

func TestPivotInferenceSurvivesRestartAndRequiresNovelEdge(t *testing.T) {
	e, sink := lateralFixture(t, DefaultPolicy(), 100)
	first := attempt("192.0.2.1", "192.0.2.2", 22, "a-b")
	second := attempt("192.0.2.2", "192.0.2.3", 22, "b-c")
	if err := e.Observe(testTime.Add(2*time.Second), first); err != nil {
		t.Fatal(err)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := Open(e.config, sink)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if err := restarted.Observe(testTime.Add(3*time.Second), second); err != nil {
		t.Fatal(err)
	}
	if detectorCount(sink, "lateral.pivot-sequence") != 1 || detectorCount(sink, "lateral.new-ssh-edge") != 2 {
		t.Fatal("restart lost pivot evidence")
	}
	if err := restarted.Change("approve-changes", []string{factID(second)}, "approved jump-host relationship"); err != nil {
		t.Fatal(err)
	}
	second.Token = "approved-retry"
	if err := restarted.Observe(testTime.Add(4*time.Second), second); err != nil {
		t.Fatal(err)
	}
	if detectorCount(sink, "lateral.pivot-sequence") != 1 {
		t.Fatal("known administrative edge reported as novel pivot")
	}
}

func TestActivityIsScopedAndGloballyBounded(t *testing.T) {
	e, sink := lateralFixture(t, DefaultPolicy(), 10)
	for i := range 100 {
		fact := attempt("192.0.2.1", "192.0.2.2", 445, fmt.Sprint(i))
		if err := e.Observe(testTime.Add(2*time.Second), fact); err != nil {
			t.Fatal(err)
		}
	}
	if len(e.Snapshot().Activity) != 10 || e.Snapshot().WindowOverflow != 90 || e.activity.Len() != 10 {
		t.Fatal("activity or expiry index grew past cap")
	}
	if detectorCount(sink, "lateral.smb-fanout") != 0 {
		t.Fatal("bounded same-host attempts became scan")
	}
	fact := attempt("192.0.2.1", "192.0.2.3", 22, "other-vlan")
	fact.Scope.VLANs = []uint16{20}
	if err := e.Observe(testTime.Add(3*time.Minute), fact); err != nil {
		t.Fatal(err)
	}
	if detectorCount(sink, "lateral.new-ssh-edge") != 0 {
		t.Fatal("untagged local prefix leaked into another VLAN")
	}
}
