package rules

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/types"
)

func dnsQueryRecord(at int64, src, name string) *types.DNS {
	return &types.DNS{Timestamp: (1_700_000_000 + at) * int64(time.Second), SrcIP: src, DstIP: "8.8.8.8", Questions: []*types.DNSQuestion{{Name: name}}}
}

func groupedDNSEngine(t *testing.T, threshold int) (*Engine, *[]*types.Alert) {
	t.Helper()
	var alerts []*types.Alert
	config := &Config{Rules: []*Rule{{Name: "beacon", Type: "DNS", Expression: "len(Questions) > 0", Severity: "low", Enabled: true, Threshold: threshold, ThresholdWindow: 600, GroupBy: []string{"SrcIP", "Questions.Name"}}}}
	e, err := NewAuditReplay(config, alertWriterFunc(func(a *types.Alert) error { alerts = append(alerts, a); return nil }))
	if err != nil {
		t.Fatal(err)
	}
	return e.engine, &alerts
}

// Embedded rules are replayed unscoped. A group_by threshold there used to
// return "scoped rules require capture/source scope" and fail the analysis.
func TestUnscopedGroupedThresholdCountsPerGroup(t *testing.T) {
	e, alerts := groupedDNSEngine(t, 3)
	feed := func(at int64, src, name string) {
		t.Helper()
		if _, err := e.Evaluate(dnsQueryRecord(at, src, name)); err != nil {
			t.Fatal(err)
		}
	}
	feed(0, "10.0.0.1", "a.example")
	feed(1, "10.0.0.1", "b.example")
	feed(2, "10.0.0.2", "a.example")
	feed(3, "10.0.0.1", "a.example")
	if len(*alerts) != 0 {
		t.Fatalf("groups combined: %d alerts", len(*alerts))
	}
	feed(4, "10.0.0.1", "a.example")
	if len(*alerts) != 1 {
		t.Fatalf("third match in one group: %d alerts", len(*alerts))
	}
	// The window drops old matches: two now and one after 601 s do not fire.
	feed(10, "10.0.0.2", "a.example")
	feed(700, "10.0.0.2", "a.example")
	if len(*alerts) != 1 {
		t.Fatalf("expired matches counted: %d alerts", len(*alerts))
	}
	// Records without a query name are not counted.
	if _, err := e.Evaluate(&types.DNS{Timestamp: 1, SrcIP: "10.0.0.9"}); err != nil {
		t.Fatal(err)
	}
}

func TestUnscopedGroupedThresholdIsBounded(t *testing.T) {
	e, alerts := groupedDNSEngine(t, 100)
	for i := range maxGroupedThresholdGroups + 5_000 {
		if _, err := e.Evaluate(dnsQueryRecord(int64(i%500), fmt.Sprintf("10.%d.%d.%d", i>>16, i>>8&255, i&255), "noise.example")); err != nil {
			t.Fatal(err)
		}
	}
	g := e.grouped["beacon"]
	if len(g.groups) > maxGroupedThresholdGroups || g.evictions == 0 || g.entries > maxGroupedThresholdMatches {
		t.Fatalf("groups %d entries %d evictions %d", len(g.groups), g.entries, g.evictions)
	}
	// An active group stays most recently used and still reaches its threshold.
	for i := range 100 {
		if _, err := e.Evaluate(dnsQueryRecord(int64(500+i), "192.0.2.7", "c2.example")); err != nil {
			t.Fatal(err)
		}
		if _, err := e.Evaluate(dnsQueryRecord(int64(500+i), fmt.Sprintf("172.16.%d.%d", i, i), "noise.example")); err != nil {
			t.Fatal(err)
		}
	}
	if len(*alerts) != 1 {
		t.Fatalf("active beacon under load: %d alerts", len(*alerts))
	}
	if stats := e.GetStats(); stats["grouped_evictions"].(uint64) == 0 {
		t.Fatalf("stats %v", stats)
	}
}

func TestDistinctTrackerIsBoundedAndScannerStillFires(t *testing.T) {
	var alerts []*types.Alert
	config := &Config{Rules: []*Rule{{Name: "scan", Type: "TCP", Expression: "SYN", Severity: "info", Enabled: true, DistinctField: "DstPort", DistinctThreshold: 100, ThresholdWindow: 60}}}
	replay, err := NewAuditReplay(config, alertWriterFunc(func(a *types.Alert) error { alerts = append(alerts, a); return nil }))
	if err != nil {
		t.Fatal(err)
	}
	base := int64(1_700_000_000) * int64(time.Second)
	for i := range maxDistinctSources + 20_000 {
		syn := &types.TCP{Timestamp: base + int64(i), SrcIP: fmt.Sprintf("spoof-%d", i), DstIP: "192.0.2.1", DstPort: 80, SYN: true}
		if _, err := replay.Evaluate(syn); err != nil {
			t.Fatal(err)
		}
	}
	tracker := replay.engine.distinctTrackers["scan"]
	if len(tracker.seen) > maxDistinctSources || tracker.evictions == 0 || len(tracker.elems) != len(tracker.seen) {
		t.Fatalf("sources %d evictions %d", len(tracker.seen), tracker.evictions)
	}
	for port := range int32(100) {
		syn := &types.TCP{Timestamp: base + int64(200_000+port), SrcIP: "203.0.113.9", DstIP: "192.0.2.1", DstPort: port + 1, SYN: true}
		if _, err := replay.Evaluate(syn); err != nil {
			t.Fatal(err)
		}
	}
	if len(alerts) != 1 {
		t.Fatalf("scanner alerts %d", len(alerts))
	}
}

// The validator and the extractor must accept the same paths, or a rule
// compiles and then silently never matches.
func TestFieldPathValidatorMatchesExtractor(t *testing.T) {
	dns := &types.DNS{SrcIP: "10.0.0.1", ID: 7, Questions: []*types.DNSQuestion{{Name: "c2.example.org", Type: 1}, {Name: "other"}}}
	for path, want := range map[string]string{"SrcIP": "10.0.0.1", "ID": "7", "Questions.Name": "c2.example.org", "Questions.Type": "1"} {
		if _, err := fieldPathType(reflect.TypeOf(dns), path); err != nil {
			t.Errorf("%s rejected: %v", path, err)
		}
		if got := extractStringField(dns, path); got != want {
			t.Errorf("%s = %q, want %q", path, got, want)
		}
	}
	for _, path := range []string{"", "Questions", "QR", "Nope", "Questions.Nope", "SrcIP.Len", "Questions.Name.X", "A.B.C.D.E", "Answers"} {
		if _, err := fieldPathType(reflect.TypeOf(dns), path); err == nil {
			t.Errorf("%q accepted", path)
		}
	}
	if got := extractStringField(&types.DNS{}, "Questions.Name"); got != "" {
		t.Fatalf("empty questions: %q", got)
	}
	var nilDNS *types.DNS
	if got := extractStringField(nilDNS, "SrcIP"); got != "" {
		t.Fatalf("nil record: %q", got)
	}
}

func TestDistinctFieldIsValidated(t *testing.T) {
	config := &Config{Rules: []*Rule{{Name: "r", Type: "TCP", Expression: "SYN", Severity: "info", Enabled: true, DistinctField: "DstPrt", DistinctThreshold: 2}}}
	if err := CompileRules(config); err == nil || !strings.Contains(err.Error(), "distinct_field") {
		t.Fatalf("typo compiled: %v", err)
	}
}

func TestJoinFieldsResolveDottedPaths(t *testing.T) {
	dns, _ := parseRecordType("DNS")
	httpType, _ := parseRecordType("HTTP")
	if err := validateJoinFields([]string{"Questions.Name"}, dns, []string{"Host"}, httpType); err != nil {
		t.Fatalf("string leaves rejected: %v", err)
	}
	if err := validateJoinFields([]string{"Questions.Type"}, dns, []string{"Host"}, httpType); err == nil {
		t.Fatal("int and string join accepted")
	}
}

// group_by without capture_time now loads from a rules directory.
func TestNewEngineAcceptsUnscopedGroupBy(t *testing.T) {
	if _, err := NewEngine("examples", &MockAlertWriter{}); err != nil {
		t.Fatal(err)
	}
}

// SavedCopy must carry every exported field; a hand-built copy dropped
// group_by and silently turned grouped thresholds into global ones.
func TestSavedCopyKeepsEveryExportedField(t *testing.T) {
	rule := fullyPopulatedRule(t)
	saved := rule.SavedCopy()
	got, want := reflect.ValueOf(saved), reflect.ValueOf(*rule)
	for i := range got.NumField() {
		field := got.Type().Field(i)
		if field.IsExported() && !reflect.DeepEqual(got.Field(i).Interface(), want.Field(i).Interface()) {
			t.Errorf("%s was not copied", field.Name)
		}
	}
	if saved.compiled != nil || saved.compiledDigest != "" {
		t.Fatal("compiled state copied")
	}
}

// fullyPopulatedRule sets every exported field to a non-zero value.
func fullyPopulatedRule(t *testing.T) *Rule {
	t.Helper()
	rule := &Rule{Name: "r", Description: "d", Type: "DNS", Expression: "true", Severity: "low", MITRE: []string{"T1"}, Tags: []string{"x"}, Enabled: true,
		Threshold: 5, ThresholdWindow: 60, GroupBy: []string{"SrcIP"}, FoldCase: true, DedupeBy: []string{"SrcIP"}, DedupeWindow: 60, DistinctField: "DstIP", DistinctThreshold: 3,
		Actions: []*ResponseAction{{Type: "log"}}, Sequence: &Sequence{After: "true", GroupBy: []string{"SrcIP"}}}
	v := reflect.ValueOf(rule).Elem()
	for i := range v.NumField() {
		if v.Type().Field(i).IsExported() && v.Field(i).IsZero() {
			t.Fatalf("fixture leaves %s unset; extend it", v.Type().Field(i).Name)
		}
	}
	return rule
}

// Capture workers deliver records out of timestamp order. A window anchored
// at the current record ignored newer values, so a CLI port scan never fired.
func TestDistinctAndGroupedCountsTolerateReordering(t *testing.T) {
	var alerts []*types.Alert
	config := &Config{Rules: []*Rule{
		{Name: "scan", Type: "TCP", Expression: "SYN", Severity: "info", Enabled: true, DistinctField: "DstPort", DistinctThreshold: 100, ThresholdWindow: 60},
		{Name: "beacon", Type: "DNS", Expression: "true", Severity: "low", Enabled: true, Threshold: 50, ThresholdWindow: 600, GroupBy: []string{"SrcIP", "Questions.Name"}},
	}}
	e, err := NewEngineFromConfig(config, alertWriterFunc(func(a *types.Alert) error { alerts = append(alerts, a); return nil }))
	if err != nil {
		t.Fatal(err)
	}
	base := int64(1_700_000_000) * int64(time.Second)
	// Newest first: every later record is older than everything seen so far.
	for i := int32(99); i >= 0; i-- {
		if _, err := e.Evaluate(&types.TCP{Timestamp: base + int64(i)*int64(time.Millisecond), SrcIP: "10.0.0.5", DstPort: i + 1, SYN: true}); err != nil {
			t.Fatal(err)
		}
	}
	for i := 49; i >= 0; i-- {
		if _, err := e.Evaluate(dnsQueryRecord(int64(i), "10.0.0.5", "c2.example.org")); err != nil {
			t.Fatal(err)
		}
	}
	names := map[string]int{}
	for _, a := range alerts {
		names[a.RuleName]++
	}
	if names["scan"] != 1 || names["beacon"] != 1 {
		t.Fatalf("alerts %v", names)
	}
	// A record older than the window behind the newest one is not counted.
	e2, _ := NewEngineFromConfig(&Config{Rules: config.Rules[1:]}, alertWriterFunc(func(a *types.Alert) error { alerts = append(alerts, a); return nil }))
	before := len(alerts)
	if _, err := e2.Evaluate(dnsQueryRecord(10_000, "10.0.0.5", "c2.example.org")); err != nil {
		t.Fatal(err)
	}
	for i := range 60 {
		if _, err := e2.Evaluate(dnsQueryRecord(int64(i), "10.0.0.5", "c2.example.org")); err != nil {
			t.Fatal(err)
		}
	}
	if len(alerts) != before {
		t.Fatal("matches outside the window counted")
	}
}

// Per-victim floods need 10,000 matches per group; one timestamp per match
// overran the shared budget and evicted every victim before it fired.
func TestGroupedFloodCountsEveryVictimWithinBudget(t *testing.T) {
	var alerts []*types.Alert
	config := &Config{Rules: []*Rule{
		{Name: "flood", Type: "TCP", Expression: "SYN", Severity: "high", Enabled: true, Threshold: 10_000, ThresholdWindow: 10, GroupBy: []string{"DstIP"}},
		{Name: "brute", Type: "TCP", Expression: "SYN && DstPort == 22", Severity: "high", Enabled: true, Threshold: 3, ThresholdWindow: 120, GroupBy: []string{"SrcIP", "DstIP"}},
	}}
	replay, err := NewAuditReplay(config, alertWriterFunc(func(a *types.Alert) error { alerts = append(alerts, a); return nil }))
	if err != nil {
		t.Fatal(err)
	}
	base := int64(1_700_000_000) * int64(time.Second)
	feed := func(at int64, src, dst string, port int32) {
		t.Helper()
		if _, err := replay.Evaluate(&types.TCP{Timestamp: base + at, SrcIP: src, DstIP: dst, DstPort: port, SYN: true}); err != nil {
			t.Fatal(err)
		}
	}
	feed(0, "198.51.100.7", "192.0.2.22", 22)
	feed(1, "198.51.100.7", "192.0.2.22", 22)
	for i := range 30 * 10_000 {
		feed(int64(i)*20_000, "203.0.113.1", fmt.Sprintf("192.0.2.%d", i%30), 80)
	}
	if len(alerts) != 30 {
		t.Fatalf("flood alerts %d, want one per victim", len(alerts))
	}
	if g := replay.engine.grouped["flood"]; g.evictions != 0 {
		t.Fatalf("flood evicted %d groups", g.evictions)
	}
	// The flood must not have evicted another rule's pending group.
	feed(2, "198.51.100.7", "192.0.2.22", 22)
	if len(alerts) != 31 || alerts[30].RuleName != "brute" {
		t.Fatalf("brute-force group lost to the flood: %d alerts", len(alerts))
	}
}

func TestBucketedGroupedWindowMatchesExact(t *testing.T) {
	window := int64(10 * time.Second)
	width := window / groupedBuckets
	for _, tc := range []struct {
		name   string
		spread int64
		fires  bool
	}{
		{"inside window", window - width, true},
		{"outside window by two buckets", window + 2*width, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &groupedCount{}
			fired := false
			const threshold = 1000
			for i := range int64(threshold) {
				// Deliver out of order: odd matches arrive late.
				at := i * tc.spread / (threshold - 1)
				if i%2 == 1 && i > 1 {
					at = (i - 1) * tc.spread / (threshold - 1)
				}
				fired = c.addBucketed(at, window, threshold) || fired
			}
			if fired != tc.fires || len(c.buckets) > groupedBuckets+1 {
				t.Fatalf("fired %v buckets %d", fired, len(c.buckets))
			}
		})
	}
}

func TestFoldCaseGroupsDNSNamesCaseInsensitively(t *testing.T) {
	var alerts []*types.Alert
	config := &Config{Rules: []*Rule{{Name: "beacon", Type: "DNS", Expression: "len(Questions) > 0", Severity: "low", Enabled: true,
		Threshold: 3, ThresholdWindow: 600, GroupBy: []string{"SrcIP", "Questions.Name"}, FoldCase: true}}}
	replay, err := NewAuditReplay(config, alertWriterFunc(func(a *types.Alert) error { alerts = append(alerts, a); return nil }))
	if err != nil {
		t.Fatal(err)
	}
	for i, name := range []string{"C2.Example", "c2.example", "c2.EXAMPLE"} {
		if _, err := replay.Evaluate(dnsQueryRecord(int64(i), "10.0.0.1", name)); err != nil {
			t.Fatal(err)
		}
	}
	if len(alerts) != 1 {
		t.Fatalf("case variants split the group: %d alerts", len(alerts))
	}
	if err := CompileRules(&Config{Rules: []*Rule{{Name: "x", Type: "DNS", Expression: "true", Severity: "low", Enabled: true, Threshold: 2, FoldCase: true}}}); err == nil {
		t.Fatal("fold_case without group_by compiled")
	}
	if foldASCII("İ.ExAmple") != "İ.example" {
		t.Fatal("non-ASCII folded")
	}
}
