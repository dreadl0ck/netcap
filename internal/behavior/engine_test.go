package behavior

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/types"
)

type testSink struct {
	alerts []*types.Alert
	err    error
}

func (s *testSink) WriteAlert(alert *types.Alert) error {
	if s.err != nil {
		return s.err
	}
	s.alerts = append(s.alerts, proto.Clone(alert).(*types.Alert))
	return nil
}

var testTime = time.Unix(1700000000, 0)

func testFact() Fact {
	return Fact{Scope: Scope{Sensor: "sensor", Interface: "en0"}, Kind: "edge", SrcIP: "192.0.2.1", DstIP: "192.0.2.2"}
}

func testEngine(t *testing.T, cap int) (*Engine, *testSink) {
	t.Helper()
	sink := &testSink{}
	e, err := Open(Config{Path: filepath.Join(t.TempDir(), "Behavior.json"), MinLearning: time.Second, MinSamples: 2, MaxFacts: cap}, sink)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Close() })
	return e, sink
}

func learn(t *testing.T, e *Engine, facts ...Fact) {
	t.Helper()
	for _, at := range []time.Time{testTime, testTime.Add(time.Second)} {
		if err := e.Observe(at, facts...); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.Change("approve", nil, "fixture learning reviewed"); err != nil {
		t.Fatal(err)
	}
}

func TestApprovedBaselineDoesNotLearnDeviations(t *testing.T) {
	e, sink := testEngine(t, 10)
	fact := testFact()
	learn(t, e, fact)
	baseline := e.Snapshot()
	newFact := fact
	newFact.DstIP = "192.0.2.3"
	if err := e.Observe(testTime.Add(2*time.Second), fact, newFact); err != nil {
		t.Fatal(err)
	}
	if len(sink.alerts) != 1 {
		t.Fatalf("alerts = %d", len(sink.alerts))
	}
	var evidence Evidence
	if err := json.Unmarshal([]byte(sink.alerts[0].MatchedRecord), &evidence); err != nil {
		t.Fatal(err)
	}
	if evidence.BaselineID != baseline.BaselineID || evidence.Version != 1 || evidence.Observed.DstIP != newFact.DstIP {
		t.Fatalf("evidence = %+v", evidence)
	}
	if len(e.Snapshot().Approved) != 1 {
		t.Fatal("deviation became trusted")
	}
	if err := e.Observe(testTime.Add(3*time.Second), newFact); err != nil {
		t.Fatal(err)
	}
	if len(sink.alerts) != 1 {
		t.Fatal("dedup failed")
	}
	if err := e.Change("approve-changes", []string{factID(newFact)}, "approved peer"); err != nil {
		t.Fatal(err)
	}
	if err := e.Observe(testTime.Add(4*time.Second), newFact); err != nil {
		t.Fatal(err)
	}
	if len(sink.alerts) != 1 || e.Snapshot().Version != 2 {
		t.Fatal("approval failed")
	}
	if evidence.BaselineID != baseline.BaselineID {
		t.Fatal("historical evidence changed")
	}
}

func TestBaselineRestartAndExclusiveLease(t *testing.T) {
	e, sink := testEngine(t, 10)
	learn(t, e, testFact())
	before := e.Snapshot()
	if duplicate, err := Open(e.config, sink); err == nil {
		_ = duplicate.Close()
		t.Fatal("same baseline opened by two writers")
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := Open(e.config, sink)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if !reflect.DeepEqual(before, restarted.Snapshot()) {
		t.Fatal("snapshot changed across restart")
	}
	if err := e.Observe(testTime, testFact()); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("closed observe = %v", err)
	}
}

func TestScopeAndARPConflict(t *testing.T) {
	e, sink := testEngine(t, 10)
	binding := testFact()
	binding.Kind, binding.DstIP, binding.MAC = "binding", "", "00:11:22:33:44:55"
	binding.Provenance = "arp"
	learn(t, e, binding)
	other := binding
	other.Scope.VLANs = []uint16{20}
	if err := e.Observe(testTime.Add(2*time.Second), other); err != nil {
		t.Fatal(err)
	}
	conflict := binding
	conflict.MAC = "00:11:22:33:44:66"
	if err := e.Observe(testTime.Add(3*time.Second), conflict); err != nil {
		t.Fatal(err)
	}
	if len(sink.alerts) != 2 || sink.alerts[0].Name != "baseline.new-binding" || sink.alerts[1].Name != "baseline.arp-conflict" {
		t.Fatalf("alerts = %v", sink.alerts)
	}
}

func TestBaselineControls(t *testing.T) {
	e, sink := testEngine(t, 10)
	if err := e.Change("approve", nil, "too early"); err == nil {
		t.Fatal("approved empty baseline")
	}
	learn(t, e, testFact())
	if err := e.Change("pause", nil, "maintenance"); err != nil {
		t.Fatal(err)
	}
	before := e.Snapshot()
	if err := e.Observe(testTime.Add(time.Hour), testFact()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, e.Snapshot()) {
		t.Fatal("pause changed samples")
	}
	if err := e.Change("resume", nil, "maintenance finished"); err != nil {
		t.Fatal(err)
	}
	fact := testFact()
	fact.DstIP = "192.0.2.3"
	if err := e.Observe(testTime.Add(2*time.Second), fact); err != nil {
		t.Fatal(err)
	}
	if err := e.Change("suppress", []string{factID(fact)}, "approved exception"); err != nil {
		t.Fatal(err)
	}
	if err := e.Observe(testTime.Add(time.Hour), fact); err != nil {
		t.Fatal(err)
	}
	if len(sink.alerts) != 1 {
		t.Fatal("suppression failed")
	}
	if err := e.Change("unsuppress", []string{factID(fact)}, "exception expired"); err != nil {
		t.Fatal(err)
	}
	if err := e.Observe(testTime.Add(2*time.Hour), fact); err != nil {
		t.Fatal(err)
	}
	if len(sink.alerts) != 2 {
		t.Fatal("unsuppress failed")
	}
	if err := e.Change("relearn", nil, "network changed"); err != nil {
		t.Fatal(err)
	}
	if snapshot := e.Snapshot(); snapshot.Mode != Learning || snapshot.Samples != 0 || len(snapshot.Approved) != 1 || len(snapshot.Observed) != 0 || len(snapshot.Suppressed) != 0 {
		t.Fatalf("relearn = %+v", snapshot)
	}
	if err := e.Change("reset", nil, "retire baseline"); err != nil {
		t.Fatal(err)
	}
	if snapshot := e.Snapshot(); snapshot.Version != 2 || len(snapshot.Approved) != 0 {
		t.Fatalf("reset = %+v", snapshot)
	}
}

func TestBaselineBoundsAndAtomicValidation(t *testing.T) {
	e, _ := testEngine(t, 2)
	fact := testFact()
	invalid := fact
	invalid.SrcIP = "not-an-ip"
	if err := e.Observe(testTime, fact, invalid); err == nil {
		t.Fatal("accepted invalid fact")
	}
	if e.Snapshot().Samples != 0 {
		t.Fatal("invalid batch partially applied")
	}
	for i := range 1000 {
		fact.Value = time.Duration(i).String()
		if err := e.Observe(testTime.Add(time.Duration(i)*time.Second), fact); err != nil {
			t.Fatal(err)
		}
	}
	state := e.Snapshot()
	if len(state.Observed) != 2 || state.Overflow != 998 {
		t.Fatalf("bound = %d, overflow = %d", len(state.Observed), state.Overflow)
	}
	if err := e.Change("approve", nil, "overflowed"); err == nil {
		t.Fatal("approved overflowed learning")
	}
}

func TestBaselineReplayOrderAndSnapshotIsolation(t *testing.T) {
	a, _ := testEngine(t, 10)
	b, _ := testEngine(t, 10)
	fact := testFact()
	for _, at := range []time.Time{testTime, testTime.Add(time.Second)} {
		if err := a.Observe(at, fact); err != nil {
			t.Fatal(err)
		}
	}
	for _, at := range []time.Time{testTime.Add(time.Second), testTime} {
		if err := b.Observe(at, fact); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.Change("approve", nil, "in order"); err != nil {
		t.Fatal(err)
	}
	if err := b.Change("approve", nil, "out of order"); err != nil {
		t.Fatal(err)
	}
	if a.Snapshot().BaselineID != b.Snapshot().BaselineID || !reflect.DeepEqual(a.Snapshot().Observed, b.Snapshot().Observed) || b.Snapshot().OutOfOrder != 1 {
		t.Fatal("replay changed semantic baseline")
	}
	snapshot := a.Snapshot()
	clear(snapshot.Observed)
	if len(a.Snapshot().Observed) != 1 {
		t.Fatal("snapshot caller mutated engine")
	}
}

func TestBaselinePersistenceFailureLeavesDecisionUnapplied(t *testing.T) {
	e, _ := testEngine(t, 10)
	learn(t, e, testFact())
	before := e.Snapshot()
	e.config.Path = filepath.Join(e.config.Path, "impossible", "baseline")
	if err := e.Change("pause", nil, "cannot persist"); err == nil {
		t.Fatal("persistence failure returned success")
	}
	if !reflect.DeepEqual(before, e.Snapshot()) {
		t.Fatal("failed decision changed live state")
	}
}

func TestBaselineSinkFailureIsSticky(t *testing.T) {
	e, sink := testEngine(t, 10)
	learn(t, e, testFact())
	want := errors.New("sink failure")
	sink.err = want
	fact := testFact()
	fact.DstIP = "192.0.2.3"
	if err := e.Observe(testTime.Add(2*time.Second), fact); !errors.Is(err, want) {
		t.Fatalf("sink error = %v", err)
	}
	if err := e.Observe(testTime.Add(3*time.Second), fact); !errors.Is(err, want) {
		t.Fatal("failure lost")
	}
	if err := e.Close(); !errors.Is(err, want) {
		t.Fatal("close lost failure")
	}
}

func TestBaselineRejectsCorruptSnapshot(t *testing.T) {
	e, sink := testEngine(t, 10)
	learn(t, e, testFact())
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(e.config.Path)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []func(*Snapshot){
		func(s *Snapshot) { s.Schema++ }, func(s *Snapshot) { s.Mode = "enforcing" },
		func(s *Snapshot) { s.BaselineID = "bad" }, func(s *Snapshot) { s.MaxFacts = 0 },
		func(s *Snapshot) {
			for id, o := range s.Observed {
				o.LastSeen = 0
				s.Observed[id] = o
			}
		},
	} {
		var state Snapshot
		_ = json.Unmarshal(data, &state)
		mutation(&state)
		bad, _ := json.Marshal(state)
		if err := os.WriteFile(e.config.Path, bad, 0600); err != nil {
			t.Fatal(err)
		}
		if opened, err := Open(e.config, sink); err == nil {
			_ = opened.Close()
			t.Fatal("accepted corrupt baseline")
		}
		got, _ := os.ReadFile(e.config.Path)
		if string(got) != string(bad) {
			t.Fatal("corrupt baseline overwritten")
		}
	}
}

func TestBaselineConcurrentObservations(t *testing.T) {
	e, _ := testEngine(t, 10)
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := e.Observe(testTime, testFact()); err != nil {
				t.Error(err)
			}
			_ = e.Snapshot()
		}()
	}
	wg.Wait()
	if snapshot := e.Snapshot(); snapshot.Samples != 32 || snapshot.Observed[factID(testFact())].Samples != 32 {
		t.Fatal("lost concurrent observations")
	}
}
