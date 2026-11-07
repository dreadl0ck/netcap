package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func thresholdRule(mode string, count int) Rule {
	r := deny("rate", `Method == "POST"`)
	r.Threshold = &Threshold{Mode: mode, Count: count, Window: "10s", GroupBy: "ClientIP"}
	return r
}

func TestSlidingThresholdExactAgainstUnboundedOracle(t *testing.T) {
	r := thresholdRule("sliding", 3)
	c := compiled(t, bundle(r))
	now := time.Unix(100, 0)
	c.now = func() time.Time { return now }
	history := map[string][]time.Time{}
	gaps := []time.Duration{0, 4 * time.Second, 5 * time.Second, 5 * time.Second, time.Second, time.Second, 0, 0, 9 * time.Second, time.Second, time.Nanosecond, 11 * time.Second}
	for i := 0; i < 120; i++ {
		now = now.Add(gaps[i%len(gaps)])
		ip := fmt.Sprint(i % 2)
		e := Event{ClientIP: ip, Method: "POST"}
		if i%7 == 0 {
			e.Method = "GET"
		}
		var active []time.Time
		for _, stamp := range history[ip] {
			if stamp.After(now.Add(-10 * time.Second)) {
				active = append(active, stamp)
			}
		}
		if e.Method == "POST" {
			active = append(active, now)
		}
		history[ip] = active
		want := "allow"
		if e.Method == "POST" && len(active) >= 3 {
			want = "deny"
		}
		if d := evaluate(t, c, e); d.Verdict != want {
			t.Fatalf("event %d at %s: got %s want %s; oracle=%v", i, now, d.Verdict, want, active)
		}
		stats := c.StateStats()
		if stats.Entries > 6 || stats.AccountedBytes > MaxStateBytes {
			t.Fatalf("unbounded last-N ring: %+v", stats)
		}
	}
}

func TestThresholdFixedDefaultAndSlidingDifference(t *testing.T) {
	for _, mode := range []string{"", "fixed", "sliding"} {
		r := thresholdRule(mode, 2)
		r.Threshold.Window = "1s"
		c := compiled(t, bundle(r))
		now := time.Unix(100, 0)
		c.now = func() time.Time { return now }
		if evaluate(t, c, Event{Method: "POST"}).Verdict != "allow" {
			t.Fatal(mode)
		}
		now = now.Add(900 * time.Millisecond)
		if evaluate(t, c, Event{Method: "POST"}).Verdict != "deny" {
			t.Fatal(mode)
		}
		now = now.Add(100 * time.Millisecond)
		want := "allow"
		if mode == "sliding" {
			want = "deny"
		}
		if d := evaluate(t, c, Event{Method: "POST"}); d.Verdict != want {
			t.Fatalf("%q at exact boundary: %+v", mode, d)
		}
	}
	r := thresholdRule("fixed", 1000000)
	c := compiled(t, bundle(r))
	evaluate(t, c, Event{Method: "POST"})
	if s := c.StateStats(); s.Entries != 0 || s.Groups != 1 {
		t.Fatalf("fixed integer counter allocated a history: %+v", s)
	}
}

func TestDistinctFixedAndSlidingRefreshBoundaries(t *testing.T) {
	for _, mode := range []string{"fixed", "sliding"} {
		r := thresholdRule(mode, 2)
		r.Threshold.Distinct = "Network.DstPort"
		r.Threshold.GroupBy = ""
		r.Threshold.GroupByFields = []string{"Attributes.tenant", "ClientIP"}
		c := compiled(t, bundle(r))
		start := time.Unix(100, 0)
		now := start
		c.now = func() time.Time { return now }
		for _, tc := range []struct {
			second         int
			port           int
			fixed, sliding string
		}{
			{0, 443, "allow", "allow"}, {0, 443, "allow", "allow"}, {5, 8443, "deny", "deny"}, {9, 443, "deny", "deny"}, {10, 443, "allow", "deny"}, {15, 443, "allow", "allow"}, {16, 8443, "deny", "deny"},
		} {
			now = start.Add(time.Duration(tc.second) * time.Second)
			want := tc.fixed
			if mode == "sliding" {
				want = tc.sliding
			}
			e := Event{Method: "POST", ClientIP: "client", Network: NetworkEvent{DstPort: tc.port}, Attributes: map[string]string{"tenant": "one"}}
			if d := evaluate(t, c, e); d.Verdict != want {
				t.Fatalf("%s second=%d: %+v want %s", mode, tc.second, d, want)
			}
		}
	}
}

func TestDistinctCapacityFailureRollsBackEveryRule(t *testing.T) {
	r := thresholdRule("sliding", 2)
	r.Threshold.Distinct = "Attributes.identity"
	r.Threshold.Window = "1h"
	other := thresholdRule("fixed", 1000000)
	other.ID = "earlier"
	other.Priority = 100
	other.Threshold.Window = "1h"
	c := compiled(t, bundle(other, r))
	now := time.Unix(100, 0)
	c.now = func() time.Time { return now }
	for i := 0; i < MaxDistinct; i++ {
		evaluate(t, c, Event{Method: "POST", ClientIP: "one", Attributes: map[string]string{"identity": fmt.Sprint(i)}})
	}
	before := make(map[[32]byte]counter)
	for key, v := range c.groups {
		before[key] = v
	}
	e := Event{Method: "POST", ClientIP: "one", Attributes: map[string]string{"identity": "private-overflow-value"}}
	if d, err := c.Evaluate(e); !errors.Is(err, ErrStateCapacity) || d.Verdict != "" || strings.Contains(err.Error(), "private-overflow-value") {
		t.Fatalf("capacity failed open/leaked data: %+v %v", d, err)
	}
	for key, v := range before {
		if c.groups[key] != v {
			t.Fatal("capacity failure advanced another rule or changed a live set")
		}
	}
	if stats := c.StateStats(); stats.Entries != MaxDistinct {
		t.Fatal(stats)
	}
	now = now.Add(time.Hour)
	if d := evaluate(t, c, e); d.Verdict != "allow" {
		t.Fatal("expired distinct capacity was not reclaimed", d)
	}
}

func TestSlidingEntryBudgetAndIdleMaintenance(t *testing.T) {
	r := thresholdRule("sliding", MaxMatches)
	r.Threshold.Window = "1h"
	c := compiled(t, bundle(r))
	now := time.Unix(100, 0)
	c.now = func() time.Time { return now }
	groups := MaxStateEntries / MaxMatches
	for i := 0; i < groups; i++ {
		evaluate(t, c, Event{Method: "POST", ClientIP: fmt.Sprint(i)})
	}
	before := c.StateStats()
	if before.Entries != groups*MaxMatches || before.AccountedBytes > MaxStateBytes {
		t.Fatal(before)
	}
	if _, err := c.Evaluate(Event{Method: "POST", ClientIP: "overflow"}); !errors.Is(err, ErrStateCapacity) {
		t.Fatal("entry budget did not reject before allocation", err)
	}
	if c.StateStats() != before {
		t.Fatal("entry capacity failure mutated state")
	}
	now = now.Add(time.Hour)
	stats, err := c.Maintain()
	if err != nil || stats != (StateStats{}) {
		t.Fatalf("idle state retained: %+v %v", stats, err)
	}
	if d := evaluate(t, c, Event{Method: "POST", ClientIP: "overflow"}); d.Verdict != "allow" {
		t.Fatal(d)
	}
	budget := stateBudget{live: StateStats{AccountedBytes: MaxStateBytes - stateGroupBytes}}
	if err := budget.reserve(counter{}, 1); !errors.Is(err, ErrStateCapacity) {
		t.Fatal("staging allocation exceeded hard byte budget", err)
	}
}

func TestMaintainPartialSlidingHistoriesAndClock(t *testing.T) {
	for _, distinct := range []string{"", "Attributes.value"} {
		r := thresholdRule("sliding", 3)
		r.Threshold.Distinct = distinct
		c := compiled(t, bundle(r))
		start := time.Unix(100, 0)
		now := start
		c.now = func() time.Time { return now }
		for i, second := range []int{0, 5, 9} {
			now = start.Add(time.Duration(second) * time.Second)
			evaluate(t, c, Event{Method: "POST", Attributes: map[string]string{"value": fmt.Sprint(i)}})
		}
		now = start.Add(10 * time.Second)
		stats, err := c.Maintain()
		if err != nil || stats.Groups != 1 {
			t.Fatal(stats, err)
		}
		for _, v := range c.groups {
			if v.count != 2 {
				t.Fatalf("exclusive lower boundary not removed: %+v", v)
			}
		}
		if distinct != "" && stats.Entries != 2 {
			t.Fatal("idle distinct timestamps not compacted", stats)
		}
		before := c.StateStats()
		now = start
		if _, err := c.Maintain(); !errors.Is(err, ErrStateClock) {
			t.Fatal("backwards maintenance clock accepted", err)
		}
		if _, err := c.Evaluate(Event{Method: "POST", Attributes: map[string]string{"value": "private"}}); !errors.Is(err, ErrStateClock) {
			t.Fatal("backwards event clock accepted", err)
		}
		if c.StateStats() != before {
			t.Fatal("clock failure changed state")
		}
		now = start.Add(19 * time.Second)
		if stats, err := c.Maintain(); err != nil || stats.Groups != 0 || stats.Entries != 0 {
			t.Fatal("idle expiry did not clear state", stats, err)
		}
	}
}

func TestTupleGroupingTypedDigestAndMapAvailability(t *testing.T) {
	r := thresholdRule("sliding", 2)
	r.Threshold.GroupBy = ""
	r.Threshold.GroupByFields = []string{"Attributes.tenant", "Attributes.user"}
	c := compiled(t, bundle(r))
	copy := c.Bundle()
	copy.Rules[0].Threshold.GroupByFields[0] = "Host"
	r.Threshold.GroupByFields[1] = "Path"
	a := Event{Method: "POST", Attributes: map[string]string{"tenant": "a\x00b", "user": "c"}}
	b := Event{Method: "POST", Attributes: map[string]string{"tenant": "a", "user": "b\x00c"}}
	if evaluate(t, c, a).Verdict != "allow" || evaluate(t, c, b).Verdict != "allow" || evaluate(t, c, a).Verdict != "deny" {
		t.Fatal("tuple encoding collided or grouping slice mutated")
	}
	before := c.StateStats()
	if _, err := c.Evaluate(Event{Method: "POST", Attributes: map[string]string{"tenant": "secret"}}); !errors.Is(err, ErrMissingStateField) || strings.Contains(err.Error(), "secret") {
		t.Fatal("missing tuple field silently became a global group", err)
	}
	if c.StateStats() != before {
		t.Fatal("missing field advanced state")
	}
	ka, _ := stateKey("test", "TLS.Encrypted", nil, Event{TLS: TLSEvent{Encrypted: true}})
	kb, _ := stateKey("test", "Attributes.value", nil, Event{Attributes: map[string]string{"value": "true"}})
	if ka == kb {
		t.Fatal("field/type tags missing from state key")
	}
	explanation, err := c.Explain(a)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(explanation)
	if strings.Contains(string(raw), "tenant") || strings.Contains(string(raw), `a\u0000b`) {
		t.Fatal("explanation leaked grouping values", string(raw))
	}
}

func TestThresholdReplayMirrorsAndDoesNotAdvanceLiveState(t *testing.T) {
	for _, distinct := range []string{"", "Attributes.value"} {
		r := thresholdRule("sliding", 2)
		r.Threshold.Distinct = distinct
		c := compiled(t, bundle(r))
		evaluate(t, c, Event{Method: "POST", ClientIP: "live", Attributes: map[string]string{"value": "existing"}})
		before := c.StateStats()
		events := []Event{{Method: "POST", Attributes: map[string]string{"value": "a"}}, {Method: "POST", Attributes: map[string]string{"value": "a"}}, {Method: "POST", Attributes: map[string]string{"value": "b"}}, {Method: "GET", Attributes: map[string]string{"value": "b"}}}
		ds, err := c.Simulate(events)
		if err != nil {
			t.Fatal(err)
		}
		shadow := compiled(t, c.Bundle())
		instant := time.Now()
		shadow.now = func() time.Time { return instant }
		for i, e := range events {
			want := evaluate(t, shadow, e)
			if ds[i].Verdict != want.Verdict || ds[i].RuleID != want.RuleID || len(ds[i].Effects) != 0 {
				t.Fatalf("replay mismatch: %+v %+v", ds[i], want)
			}
		}
		if c.StateStats() != before {
			t.Fatal("replay changed live history")
		}
	}
	c := compiled(t, bundle(thresholdRule("sliding", MaxMatches)))
	if _, err := c.Simulate(make([]Event, 10000)); !errors.Is(err, ErrWorkBudget) {
		t.Fatal("sliding replay omitted state work from budget", err)
	}
	if c.StateStats().Groups != 0 {
		t.Fatal("work preflight advanced state")
	}
}

func TestConcurrentSlidingEvaluationMaintenanceAndReplay(t *testing.T) {
	c := compiled(t, bundle(thresholdRule("sliding", 8)))
	instant := time.Now()
	c.now = func() time.Time { return instant }
	var wg sync.WaitGroup
	var denied atomic.Int32
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d, err := c.Evaluate(Event{Method: "POST"})
			if err != nil {
				t.Error(err)
			}
			if d.Verdict == "deny" {
				denied.Add(1)
			}
		}()
	}
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.Maintain(); err != nil {
				t.Error(err)
			}
			_ = c.StateStats()
			if _, err := c.Simulate([]Event{{Method: "POST"}, {Method: "POST"}}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if denied.Load() != 193 || c.StateStats().Entries != 8 {
		t.Fatal("non-atomic sliding counters", denied.Load(), c.StateStats())
	}
}

func TestEffectValidationFailureDoesNotMutateSlidingHistory(t *testing.T) {
	for _, distinct := range []string{"", "Attributes.value"} {
		r := thresholdRule("sliding", 2)
		r.Threshold.Distinct = distinct
		r.Effects = []Effect{{Kind: "block_source", Target: "source", Scope: "edge", Duration: "1m"}}
		c, err := CompileWithOptions(bundle(r), CompileOptions{AllowEffects: true})
		if err != nil {
			t.Fatal(err)
		}
		now := time.Unix(100, 0)
		c.now = func() time.Time { return now }
		e := Event{Method: "POST", ClientIP: "192.0.2.5", Network: NetworkEvent{SrcIP: "192.0.2.5"}, Attributes: map[string]string{"value": "a"}}
		evaluate(t, c, e)
		key := groupKey("threshold:rate", "ClientIP", e)
		before := c.groups[key]
		stamps := append([]time.Time(nil), before.history.stamps...)
		now = now.Add(time.Millisecond)
		e.Network.SrcIP = "private-invalid-source"
		e.Attributes["value"] = "b"
		if _, err := c.Evaluate(e); err == nil || strings.Contains(err.Error(), "private-invalid-source") {
			t.Fatal("effect validation failure leaked/accepted source", err)
		}
		if c.groups[key] != before {
			t.Fatal("effect failure committed new history")
		}
		for i, stamp := range stamps {
			if before.history.stamps[i] != stamp {
				t.Fatal("staged ring aliased live timestamps")
			}
		}
		if distinct != "" && len(before.history.distinct) != 1 {
			t.Fatal("staged distinct map aliased live set")
		}
	}
}

func TestGenericRecordDistinctAndPerInstanceIsolation(t *testing.T) {
	r := thresholdRule("sliding", 2)
	r.Expression = `RecordType == "Connection"`
	r.Threshold.Distinct = "Fields.Service"
	r.Threshold.GroupBy = ""
	r.Threshold.GroupByFields = []string{"Attributes.tenant", "Fields.Source"}
	c := compiled(t, bundle(r))
	other := compiled(t, bundle(r))
	schema := RecordSchema{RecordType: "Connection", Fields: map[string]ScalarType{"Service": StringField, "Source": StringField}}
	e := Event{RecordType: "Connection", Fields: map[string]string{"Service": "ssh", "Source": "192.0.2.5"}, Attributes: map[string]string{"tenant": "one"}}
	if err := schema.Validate(e); err != nil {
		t.Fatal(err)
	}
	if evaluate(t, c, e).Verdict != "allow" || evaluate(t, c, e).Verdict != "allow" {
		t.Fatal("duplicate native record counted twice")
	}
	e.Fields["Service"] = "telnet"
	if evaluate(t, c, e).Verdict != "deny" || evaluate(t, other, e).Verdict != "allow" {
		t.Fatal("native distinct correlation or per-instance isolation failed")
	}
	if c.Revision() != other.Revision() {
		t.Fatal("identical policy revisions differ")
	}
	delete(e.Fields, "Service")
	before := c.StateStats()
	if _, err := c.Evaluate(e); !errors.Is(err, ErrMissingStateField) || !strings.Contains(err.Error(), "Fields.Service") {
		t.Fatal("missing native scalar did not return field-only diagnostics", err)
	}
	if c.StateStats() != before {
		t.Fatal("missing native scalar changed state")
	}
}
