package rules

import (
	"fmt"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/types"
)

// sequenceEngine builds an engine with one gated rule and a capturing writer.
func sequenceEngine(t *testing.T, seq *Sequence, expression string) (*Engine, *[]*types.Alert) {
	t.Helper()
	rule := &Rule{
		Name: "gated", Type: "Modbus", Severity: "high", Enabled: true,
		Expression: expression, Sequence: seq,
	}
	config := &Config{Rules: []*Rule{rule}}
	if err := CompileRules(config); err != nil {
		t.Fatal(err)
	}
	var written []*types.Alert
	engine := &Engine{
		config:            config,
		alertWriter:       alertWriterFunc(func(a *types.Alert) error { written = append(written, a); return nil }),
		recentAlerts:      make(map[string]int64),
		dedupWindow:       0,
		ruleCounters:      make(map[string]*rateCounter),
		rateLimit:         100000,
		thresholdTrackers: make(map[string]*thresholdTracker),
		distinctTrackers:  make(map[string]*distinctTracker),
		sequenceTrackers:  make(map[string]*sequenceTracker),
		actionStats:       &ActionStats{},
	}
	return engine, &written
}

type alertWriterFunc func(*types.Alert) error

func (f alertWriterFunc) WriteAlert(a *types.Alert) error { return f(a) }
func (f alertWriterFunc) Close() error                    { return nil }

// sequenceEpoch keeps test timestamps in a realistic range; the engine falls
// back to wall-clock time for records reporting a zero timestamp.
const sequenceEpoch = 1700000000

func modbusAt(second int64, role string, fc int32, address uint32) *types.Modbus {
	return &types.Modbus{
		Timestamp: (sequenceEpoch + second) * int64(time.Second), MessageRole: role, ParseStatus: "valid",
		FunctionCode: fc, SrcIP: "192.0.2.10", DstIP: "192.0.2.20", UnitID: 1,
		Bank: "holding_registers", HasAddress: true, Address: address, Quantity: 1,
	}
}

func TestSequenceGatesOnEarlierRecord(t *testing.T) {
	seq := &Sequence{
		After:   `MessageRole == "request" && FunctionCode == 3`,
		GroupBy: []string{"SrcIP", "DstIP", "UnitID", "Bank", "Address"},
		Within:  300,
	}
	write := `MessageRole == "request" && FunctionCode == 6`

	t.Run("read then write alerts", func(t *testing.T) {
		engine, written := sequenceEngine(t, seq, write)
		if _, err := engine.Evaluate(modbusAt(0, "request", 3, 40)); err != nil {
			t.Fatal(err)
		}
		if len(*written) != 0 {
			t.Fatal("the earlier record must not alert on its own")
		}
		if _, err := engine.Evaluate(modbusAt(10, "request", 6, 40)); err != nil {
			t.Fatal(err)
		}
		if len(*written) != 1 {
			t.Fatalf("expected one alert, got %d", len(*written))
		}
	})

	t.Run("write without a preceding read stays silent", func(t *testing.T) {
		engine, written := sequenceEngine(t, seq, write)
		if _, err := engine.Evaluate(modbusAt(10, "request", 6, 40)); err != nil {
			t.Fatal(err)
		}
		if len(*written) != 0 {
			t.Fatalf("ungated write alerted: %v", *written)
		}
	})

	t.Run("a record cannot satisfy its own precondition", func(t *testing.T) {
		// Expression and precondition both match this record.
		engine, written := sequenceEngine(t, &Sequence{
			After:   `MessageRole == "request"`,
			GroupBy: []string{"SrcIP", "UnitID"},
			Within:  300,
		}, `MessageRole == "request"`)
		if _, err := engine.Evaluate(modbusAt(0, "request", 6, 40)); err != nil {
			t.Fatal(err)
		}
		if len(*written) != 0 {
			t.Fatal("record satisfied its own precondition")
		}
		if _, err := engine.Evaluate(modbusAt(1, "request", 6, 40)); err != nil {
			t.Fatal(err)
		}
		if len(*written) != 1 {
			t.Fatalf("expected the second record to alert, got %d", len(*written))
		}
	})

	for _, tt := range []struct {
		name  string
		edit  func(*types.Modbus)
		alert bool
	}{
		{"same group", func(m *types.Modbus) {}, true},
		{"other source", func(m *types.Modbus) { m.SrcIP = "198.51.100.9" }, false},
		{"other destination", func(m *types.Modbus) { m.DstIP = "192.0.2.21" }, false},
		{"other unit", func(m *types.Modbus) { m.UnitID = 2 }, false},
		{"other bank", func(m *types.Modbus) { m.Bank = "coils" }, false},
		{"other address", func(m *types.Modbus) { m.Address = 41 }, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			engine, written := sequenceEngine(t, seq, write)
			if _, err := engine.Evaluate(modbusAt(0, "request", 3, 40)); err != nil {
				t.Fatal(err)
			}
			trigger := modbusAt(10, "request", 6, 40)
			tt.edit(trigger)
			if _, err := engine.Evaluate(trigger); err != nil {
				t.Fatal(err)
			}
			if got := len(*written) == 1; got != tt.alert {
				t.Fatalf("alert=%v, want %v", got, tt.alert)
			}
		})
	}
}

func TestSequenceWindowAndOrdering(t *testing.T) {
	seq := &Sequence{
		After:   `MessageRole == "request" && FunctionCode == 3`,
		GroupBy: []string{"SrcIP", "Address"},
		Within:  300,
	}
	write := `MessageRole == "request" && FunctionCode == 6`

	for _, tt := range []struct {
		name        string
		read, write int64
		alert       bool
	}{
		{"inside window", 0, 299, true},
		{"on the boundary", 0, 300, true},
		{"expired", 0, 301, false},
		{"write before read", 100, 50, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			engine, written := sequenceEngine(t, seq, write)
			if _, err := engine.Evaluate(modbusAt(tt.read, "request", 3, 40)); err != nil {
				t.Fatal(err)
			}
			if _, err := engine.Evaluate(modbusAt(tt.write, "request", 6, 40)); err != nil {
				t.Fatal(err)
			}
			if got := len(*written) == 1; got != tt.alert {
				t.Fatalf("alert=%v, want %v", got, tt.alert)
			}
		})
	}

	t.Run("expired observation is not reused", func(t *testing.T) {
		engine, written := sequenceEngine(t, seq, write)
		if _, err := engine.Evaluate(modbusAt(0, "request", 3, 40)); err != nil {
			t.Fatal(err)
		}
		for _, second := range []int64{400, 500} {
			if _, err := engine.Evaluate(modbusAt(second, "request", 6, 40)); err != nil {
				t.Fatal(err)
			}
		}
		if len(*written) != 0 {
			t.Fatalf("expired precondition reused: %v", *written)
		}
	})
}

// An out-of-order record is older than the stored observation. It must not
// evict it, or a later in-order pair is silently lost. Records reach the engine
// from several workers, so this ordering is not guaranteed.
func TestSequenceOutOfOrderRecordKeepsObservation(t *testing.T) {
	seq := &Sequence{
		After:   `FunctionCode == 3`,
		GroupBy: []string{"SrcIP", "Address"},
		Within:  900,
	}
	engine, written := sequenceEngine(t, seq, `FunctionCode == 6`)
	for _, record := range []*types.Modbus{
		modbusAt(100, "request", 3, 40), // read observed
		modbusAt(50, "request", 6, 40),  // late write, older than the read
		modbusAt(150, "request", 6, 40), // valid pair with the read
	} {
		if _, err := engine.Evaluate(record); err != nil {
			t.Fatal(err)
		}
	}
	if len(*written) != 1 {
		t.Fatalf("got %d alerts, want 1: a late record evicted a live observation", len(*written))
	}
}

// A failed or uncompiled precondition must surface instead of quietly
// disabling the rule.
func TestSequenceErrorsAreReported(t *testing.T) {
	engine, _ := sequenceEngine(t, &Sequence{
		After: "true", GroupBy: []string{"SrcIP"}, Within: 60,
	}, `FunctionCode == 6`)
	engine.config.Rules[0].Sequence.compiledAfter = nil
	if _, err := engine.Evaluate(modbusAt(0, "request", 6, 40)); err == nil {
		t.Fatal("expected an error for an uncompiled sequence")
	}
}

// A group_by typo or an unsupported field kind must fail at load, not silently
// prevent the rule from ever firing.
func TestSequenceGroupFieldsAreValidated(t *testing.T) {
	for _, tt := range []struct {
		name, field string
	}{
		{"typo", "SrcIp"},
		{"missing", "NoSuchField"},
		{"bool kind", "HasAddress"},
		{"bytes kind", "Payload"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{Rules: []*Rule{{
				Name: "r", Type: "Modbus", Severity: "low", Enabled: true, Expression: "true",
				Sequence: &Sequence{After: "true", GroupBy: []string{tt.field}},
			}}}
			if err := CompileRules(config); err == nil {
				t.Fatalf("group_by %q compiled", tt.field)
			}
		})
	}
	config := &Config{Rules: []*Rule{{
		Name: "r", Type: "Modbus", Severity: "low", Enabled: true, Expression: "true",
		Sequence: &Sequence{After: "true", GroupBy: []string{"SrcIP", "UnitID", "Address"}},
	}}}
	if err := CompileRules(config); err != nil {
		t.Fatalf("valid string, int and uint fields rejected: %v", err)
	}
}

// Hunt templates ship disabled, so a broken sequence must not surface only when
// an operator enables it.
func TestSequenceValidatedWhenRuleDisabled(t *testing.T) {
	config := &Config{Rules: []*Rule{{
		Name: "r", Type: "Modbus", Severity: "low", Enabled: false, Expression: "true",
		Sequence: &Sequence{After: "true"}, // no group_by
	}}}
	if err := CompileRules(config); err == nil {
		t.Fatal("invalid sequence on a disabled rule compiled")
	}
}

func TestSequenceValidationAndDefaults(t *testing.T) {
	for _, tt := range []struct {
		name string
		seq  *Sequence
	}{
		{"missing after", &Sequence{GroupBy: []string{"SrcIP"}}},
		{"missing group", &Sequence{After: "true"}},
		{"empty group field", &Sequence{After: "true", GroupBy: []string{""}}},
		{"negative window", &Sequence{After: "true", GroupBy: []string{"SrcIP"}, Within: -1}},
		{"window overflow", &Sequence{After: "true", GroupBy: []string{"SrcIP"}, Within: 900000000000}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.seq.Validate(); err == nil {
				t.Fatal("expected a validation error")
			}
			config := &Config{Rules: []*Rule{{
				Name: "r", Type: "Modbus", Severity: "low", Enabled: true,
				Expression: "true", Sequence: tt.seq,
			}}}
			if err := CompileRules(config); err == nil {
				t.Fatal("invalid sequence compiled")
			}
		})
	}
	if got := (&Sequence{}).window(); got != time.Minute {
		t.Fatalf("default window = %v, want 1m", got)
	}
	config := &Config{Rules: []*Rule{{
		Name: "r", Type: "Modbus", Severity: "low", Enabled: true,
		Expression: "true", Sequence: &Sequence{After: "NoSuchField == 1", GroupBy: []string{"SrcIP"}},
	}}}
	if err := CompileRules(config); err == nil {
		t.Fatal("invalid after expression compiled")
	}
}

// A record missing a group field cannot be related to another record.
func TestSequenceRequiresCompleteGroupKey(t *testing.T) {
	seq := &Sequence{
		After:   `FunctionCode == 3`,
		GroupBy: []string{"SrcIP", "Bank"},
		Within:  300,
	}
	engine, written := sequenceEngine(t, seq, `FunctionCode == 6`)
	read := modbusAt(0, "request", 3, 40)
	read.Bank = "" // FC8-style record with no bank
	if _, err := engine.Evaluate(read); err != nil {
		t.Fatal(err)
	}
	trigger := modbusAt(10, "request", 6, 40)
	trigger.Bank = ""
	if _, err := engine.Evaluate(trigger); err != nil {
		t.Fatal(err)
	}
	if len(*written) != 0 {
		t.Fatalf("incomplete group key correlated: %v", *written)
	}
	if _, ok := sequenceKey(read, seq.GroupBy); ok {
		t.Fatal("sequenceKey accepted a missing field")
	}
	// Distinct field values must not collide into one group, including when a
	// value contains the separator byte.
	for _, pair := range [][2]*types.Modbus{
		{{SrcIP: "a", Bank: "bc"}, {SrcIP: "ab", Bank: "c"}},
		{{SrcIP: "a\x00b", Bank: "c"}, {SrcIP: "a", Bank: "b\x00c"}},
		{{SrcIP: "1:a", Bank: "b"}, {SrcIP: "1", Bank: ":ab"}},
	} {
		a, okA := sequenceKey(pair[0], []string{"SrcIP", "Bank"})
		b, okB := sequenceKey(pair[1], []string{"SrcIP", "Bank"})
		if !okA || !okB || a == b {
			t.Fatalf("group keys collided: %q and %q", a, b)
		}
	}
}

// Ungated rules must behave exactly as before.
func TestSequenceAbsentLeavesRuleUnchanged(t *testing.T) {
	engine, written := sequenceEngine(t, nil, `FunctionCode == 6`)
	for i := range 3 {
		if _, err := engine.Evaluate(modbusAt(int64(i), "request", 6, 40)); err != nil {
			t.Fatal(err)
		}
	}
	if len(*written) != 3 {
		t.Fatalf("ungated rule produced %d alerts, want 3", len(*written))
	}
	if len(engine.sequenceTrackers) != 0 {
		t.Fatal("ungated rule allocated sequence state")
	}
}

func TestSequenceStateIsBounded(t *testing.T) {
	seq := &Sequence{
		After:   `FunctionCode == 3`,
		GroupBy: []string{"SrcIP"},
		Within:  1,
	}
	engine, _ := sequenceEngine(t, seq, `FunctionCode == 6`)
	for i := range sequenceSweepInterval * 2 {
		read := modbusAt(int64(i), "request", 3, 40)
		read.SrcIP = fmt.Sprintf("198.51.100.%d", i)
		if _, err := engine.Evaluate(read); err != nil {
			t.Fatal(err)
		}
	}
	tracker := engine.sequenceTrackers["gated"]
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	// Every observation but the most recent few has aged out of the 1s window.
	if len(tracker.seen) > 8 {
		t.Fatalf("retained %d groups, expected the window to bound them", len(tracker.seen))
	}
}
