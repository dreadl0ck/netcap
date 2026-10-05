package behavior

import (
	"encoding/json"
	"math"
	"os"
	"reflect"
	"testing"
	"time"
)

func TestLearnedRateDoesNotAdaptToMonitoringBurst(t *testing.T) {
	policy := DefaultPolicy()
	policy.WindowNS = int64(time.Second)
	e, sink := lateralFixture(t, policy, 100)
	if err := e.Change("relearn", nil, "train traffic rates"); err != nil {
		t.Fatal(err)
	}
	fact := Fact{Scope: testFact().Scope, Kind: "traffic", SrcIP: "192.0.2.1", Bytes: 100}
	for window := range 5 {
		for range 10 {
			if err := e.Observe(testTime.Add(time.Duration(window)*time.Second), fact); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := e.Change("approve", nil, "reviewed five-window capture"); err != nil {
		t.Fatal(err)
	}
	baseline := e.Snapshot()
	model := baseline.ApprovedRates[factID(fact)]
	if model.Windows != 4 || model.PacketsMean != 10 || model.BytesMean != 1000 {
		t.Fatalf("model = %+v", model)
	}
	for range 101 {
		if err := e.Observe(testTime.Add(5*time.Second), fact); err != nil {
			t.Fatal(err)
		}
	}
	if detectorCount(sink, "baseline.packet-rate") != 1 {
		t.Fatal("packet burst was not detected during active window")
	}
	fact.Bytes = 1 << 20
	for range 2 {
		if err := e.Observe(testTime.Add(5*time.Second), fact); err != nil {
			t.Fatal(err)
		}
	}
	if detectorCount(sink, "baseline.byte-rate") != 1 {
		t.Fatal("byte burst was not detected")
	}
	if !reflect.DeepEqual(baseline.ApprovedRates, e.Snapshot().ApprovedRates) || baseline.BaselineID != e.Snapshot().BaselineID {
		t.Fatal("monitoring silently adapted baseline")
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := Open(e.config, sink)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if !reflect.DeepEqual(baseline.ApprovedRates, restarted.Snapshot().ApprovedRates) {
		t.Fatal("restart lost learned rate model")
	}
}

func TestIdleWindowsUsePopulationStatistics(t *testing.T) {
	var model RateModel
	updateRate(&model, 10, 1000)
	addIdleWindows(&model, 3)
	if model.Windows != 4 || model.PacketsMean != 2.5 || model.PacketsM2 != 75 || model.BytesMean != 250 || model.BytesM2 != 750000 {
		t.Fatalf("idle model = %+v", model)
	}
	if validRateModel(RateModel{PacketsMean: math.Inf(1)}) {
		t.Fatal("accepted non-finite model")
	}
}

func TestSchemaOneMigrationKeepsApprovedIdentity(t *testing.T) {
	e, sink := testEngine(t, 10)
	learn(t, e, testFact())
	before := e.Snapshot()
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(e.config.Path)
	if err != nil {
		t.Fatal(err)
	}
	var legacy map[string]any
	if err := json.Unmarshal(data, &legacy); err != nil {
		t.Fatal(err)
	}
	legacy["schema"] = 1
	for _, key := range []string{"policy", "activity", "rates", "approvedRates", "windowOverflow"} {
		delete(legacy, key)
	}
	data, _ = json.Marshal(legacy)
	if err := os.WriteFile(e.config.Path, data, 0600); err != nil {
		t.Fatal(err)
	}
	restarted, err := Open(e.config, sink)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	state := restarted.Snapshot()
	if state.Schema != 2 || state.Version != before.Version || state.BaselineID != before.BaselineID || state.Activity == nil || state.Rates == nil {
		t.Fatal("migration changed approved semantics or lost new state")
	}
}
