package rules

import (
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/types"
)

func groupedConfig() *Config {
	return &Config{Rules: []*Rule{{Name: "scoped", Type: "TCP", Expression: "SYN", Enabled: true, Threshold: 50, ThresholdWindow: 600, GroupBy: []string{"SrcIP", "DstIP", "DstPort"}}}}
}
func scopedTCP(at int64, src string) *types.TCP {
	return &types.TCP{Timestamp: (1700000000 + at) * int64(time.Second), SrcIP: src, DstIP: "192.0.2.2", DstPort: 443, SYN: true}
}

func TestScopedCountsAndReorderedStream(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		var got []*types.Alert
		s, err := NewOrderedStream(groupedConfig(), alertWriterFunc(func(a *types.Alert) error { got = append(got, a); return nil }), "capture/source/vlan")
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 50; i++ {
			at := i
			if reverse {
				at = 49 - i
			}
			if err := s.Push(scopedTCP(int64(at), "192.0.2.1")); err != nil {
				t.Fatal(err)
			}
		}
		if n, err := s.Finish(); err != nil || n != 1 || len(got) != 1 || got[0].Timestamp != scopedTCP(49, "").Timestamp {
			t.Fatal(n, err, got)
		}
	}
	e, err := NewEngineFromConfig(groupedConfig(), alertWriterFunc(func(*types.Alert) error { return nil }))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 25; i++ {
		for _, src := range []string{"192.0.2.1", "192.0.2.3"} {
			if n, err := e.EvaluateScoped("capture", scopedTCP(int64(i), src)); n != 0 || err != nil {
				t.Fatal(n, err)
			}
		}
	}
	// Neither another source scope nor another capture can complete the count.
	for _, scope := range []string{"other-source", "other-capture"} {
		for i := 25; i < 50; i++ {
			if n, err := e.EvaluateScoped(scope, scopedTCP(int64(i), "192.0.2.1")); n != 0 || err != nil {
				t.Fatal(n, err)
			}
		}
	}
	if _, err := e.Evaluate(scopedTCP(55, "192.0.2.1")); err == nil {
		t.Fatal("unscoped grouping admitted")
	}
}

func TestScopedThresholdReclaimsExpiredEntries(t *testing.T) {
	e := &Engine{}
	rule := groupedConfig().Rules[0]
	rule.Threshold, rule.ThresholdWindow = 4, 2
	for _, step := range []struct {
		second  int64
		entries int
		alert   bool
	}{
		{1, 1, false}, {2, 2, false}, {3, 3, false},
		{4, 3, false}, {4, 0, true}, {4, 1, false},
	} {
		got, err := e.scopedThreshold("fixture", rule, scopedTCP(step.second, "192.0.2.1"))
		if err != nil || got != step.alert || e.scopedEntries != step.entries {
			t.Fatalf("second %d: alert=%t retained=%d err=%v; want alert=%t retained=%d", step.second, got, e.scopedEntries, err, step.alert, step.entries)
		}
	}
}

func TestScopedWindowBoundaryReloadAndFuture(t *testing.T) {
	cfg := groupedConfig()
	cfg.Rules[0].Threshold = 2
	var got []*types.Alert
	s, err := NewOrderedStream(cfg, alertWriterFunc(func(a *types.Alert) error { got = append(got, a); return nil }), "capture")
	if err != nil {
		t.Fatal(err)
	}
	a := scopedTCP(0, "192.0.2.1")
	if err = s.Push(a); err != nil {
		t.Fatal(err)
	}
	a.SrcIP = "mutated"
	if err = s.Reload(cfg); err == nil {
		t.Fatal("reload discarded pending evidence")
	}
	if _, err = s.Advance(scopedTCP(0, "").Timestamp); err != nil {
		t.Fatal(err)
	}
	bad := groupedConfig()
	bad.Rules[0].Expression = "invalid_field"
	if err = s.Reload(bad); err == nil {
		t.Fatal("invalid reload succeeded")
	}
	if err = s.Push(scopedTCP(600, "192.0.2.1")); err != nil {
		t.Fatal(err)
	}
	if n, err := s.Advance(scopedTCP(600, "").Timestamp); err != nil || n != 1 {
		t.Fatal("inclusive window or preserved failed-reload state lost", n, err)
	}
	if err = s.Push(scopedTCP(1, "192.0.2.1")); err == nil {
		t.Fatal("late record accepted")
	}
	if err = s.Reload(cfg); err != nil {
		t.Fatal(err)
	}
	if err = s.Push(scopedTCP(601, "192.0.2.1")); err != nil {
		t.Fatal(err)
	}
	if n, err := s.Finish(); err != nil || n != 0 {
		t.Fatal(n, err)
	}
	// Legacy counter no longer counts a future match toward an earlier event.
	e := &Engine{thresholdTrackers: make(map[string]*thresholdTracker)}
	rule := &Rule{Name: "legacy", Threshold: 2, ThresholdWindow: 60}
	e.checkThreshold(rule, scopedTCP(100, "a"))
	if e.checkThreshold(rule, scopedTCP(1, "a")) {
		t.Fatal("future timestamp satisfied earlier window")
	}
	if len(got) != 1 || got[0].SrcIP != "192.0.2.1" {
		t.Fatal("caller mutation affected owned record")
	}
}

func TestCrossTypeQualifiedCredentialJoin(t *testing.T) {
	cfg := &Config{Rules: []*Rule{{Name: "failed-auth-then-connection", Type: "TCP", Expression: "SYN", Enabled: true, Sequence: &Sequence{AfterType: "Secret", After: `AuthSuccessSet && !AuthSuccess`, GroupBy: []string{"CommunityID"}, AfterGroupBy: []string{"CommunityID"}, Within: 60}}}}
	run := func(scope string, successSet, success bool, community string, targetAt int64) []*types.Alert {
		var got []*types.Alert
		e, err := NewEngineFromConfig(cfg, alertWriterFunc(func(a *types.Alert) error { got = append(got, a); return nil }))
		if err != nil {
			t.Fatal(err)
		}
		a := &types.Secret{Timestamp: scopedTCP(1, "").Timestamp, CommunityID: "1:session", User: "fixture-user", Password: "fixture-secret", AuthSuccessSet: successSet, AuthSuccess: success}
		if _, err := e.EvaluateScoped("capture/source", a); err != nil {
			t.Fatal(err)
		}
		b := scopedTCP(targetAt, "192.0.2.1")
		b.CommunityID = community
		if _, err := e.EvaluateScoped(scope, b); err != nil {
			t.Fatal(err)
		}
		return got
	}
	got := run("capture/source", true, false, "1:session", 2)
	if len(got) != 1 || !strings.Contains(got[0].Notes, "netcapJoin") || strings.Contains(got[0].Notes, "fixture-secret") {
		t.Fatal(got)
	}
	for _, args := range []struct {
		scope        string
		set, success bool
		cid          string
		at           int64
	}{{"other", true, false, "1:session", 2}, {"capture/source", false, false, "1:session", 2}, {"capture/source", true, true, "1:session", 2}, {"capture/source", true, false, "1:other", 2}, {"capture/source", true, false, "1:session", 0}, {"capture/source", true, false, "1:session", 62}} {
		if a := run(args.scope, args.set, args.success, args.cid, args.at); len(a) != 0 {
			t.Fatal("speculative or future join", args, a)
		}
	}
}

func TestScopedCapacityAndValidation(t *testing.T) {
	cfg := groupedConfig()
	cfg.Rules[0].GroupBy = []string{"NoSuchField"}
	if _, err := NewEngineFromConfig(cfg, alertWriterFunc(func(*types.Alert) error { return nil })); err == nil {
		t.Fatal("invalid key admitted")
	}
	e, _ := NewEngineFromConfig(groupedConfig(), alertWriterFunc(func(*types.Alert) error { return nil }))
	e.scopedCounts = make(map[string]*scopedCount)
	for i := 0; i < maxScopedGroups; i++ {
		e.scopedCounts[string(rune(i))] = &scopedCount{scope: "other", last: 1}
	}
	if _, err := e.EvaluateScoped("scope", scopedTCP(1, "192.0.2.1")); !errors.Is(err, ErrStateCapacity) {
		t.Fatal(err)
	}
	if len(e.scopedCounts) != maxScopedGroups {
		t.Fatal("state evicted on refusal")
	}
	s, _ := NewOrderedStream(groupedConfig(), alertWriterFunc(func(*types.Alert) error { return nil }), "scope")
	for i := 0; i < maxPendingRecords; i++ {
		if err := s.Push(scopedTCP(1, "a")); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Push(scopedTCP(2, "a")); !errors.Is(err, ErrStateCapacity) {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(s.pending[0].record, scopedTCP(1, "a")) {
		t.Fatal("pending state changed")
	}
}

func TestSecretAlertRedaction(t *testing.T) {
	r := &Rule{Name: "secret", Type: "Secret", Expression: "AuthSuccessSet", Enabled: true}
	if err := CompileRules(&Config{Rules: []*Rule{r}}); err != nil {
		t.Fatal(err)
	}
	a, err := EvaluateRule(r, &types.Secret{Timestamp: 1, User: "private-user", Password: "private-password", Hash: "private-hash", Notes: "private-note", AuthSuccessSet: true})
	if err != nil || a == nil {
		t.Fatal(err)
	}
	if strings.Contains(a.MatchedRecord, "private-") || a.MatchedRecordSHA256 == "" {
		t.Fatal("credential leaked in alert", a)
	}
}

func TestCaptureTimeConfigDrainsAtClose(t *testing.T) {
	cfg := groupedConfig()
	cfg.CaptureTime = &CaptureTimeConfig{Scope: "capture/source", LatenessSeconds: 600}
	var got []*types.Alert
	e, err := NewEngineFromConfig(cfg, alertWriterFunc(func(a *types.Alert) error { got = append(got, a); return nil }))
	if err != nil {
		t.Fatal(err)
	}
	for i := 49; i >= 0; i-- {
		if n, err := e.Evaluate(scopedTCP(int64(i), "192.0.2.1")); err != nil || n != 0 {
			t.Fatal(n, err)
		}
	}
	if err := e.UpdateConfig(cfg); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatal("reload did not finish old-generation observations")
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatal(got)
	}
	if err := e.Close(); err != nil || len(got) != 1 {
		t.Fatal("close repeated alerts", err)
	}
	if _, err := e.Evaluate(scopedTCP(700, "192.0.2.1")); err == nil {
		t.Fatal("finalized engine accepted record")
	}
}

func TestOrderedStreamBreaksEqualRecordTiesByScope(t *testing.T) {
	for _, order := range [][2]string{{"fixture/z", "fixture/a"}, {"fixture/a", "fixture/z"}} {
		var notes []string
		cfg := &Config{Rules: []*Rule{{Name: "fixture", Type: "TCP", Expression: "SYN", Enabled: true,
			Sequence: &Sequence{AfterType: "Secret", After: "AuthSuccessSet", GroupBy: []string{"CommunityID"}, AfterGroupBy: []string{"CommunityID"}, Within: 60},
		}}}
		s, err := NewOrderedStream(cfg, alertWriterFunc(func(a *types.Alert) error {
			notes = append(notes, a.Notes)
			return nil
		}), "fixture")
		if err != nil {
			t.Fatal(err)
		}
		for _, scope := range order {
			tcp := scopedTCP(2, "192.0.2.1")
			tcp.CommunityID = "1:fixture"
			if err := s.pushScoped(scope, &types.Secret{Timestamp: tcp.Timestamp - 1, CommunityID: tcp.CommunityID, AuthSuccessSet: true}); err != nil {
				t.Fatal(err)
			}
			if err := s.pushScoped(scope, tcp); err != nil {
				t.Fatal(err)
			}
		}
		if n, err := s.Finish(); n != 2 || err != nil {
			t.Fatalf("finish: alerts=%d err=%v", n, err)
		}
		if len(notes) != 2 || !strings.Contains(notes[0], `"scope":"fixture/a"`) || !strings.Contains(notes[1], `"scope":"fixture/z"`) {
			t.Fatalf("input order %v: unexpected alert evidence order %v", order, notes)
		}
	}
}

func BenchmarkOrderedStreamEqualTime(b *testing.B) {
	for range b.N {
		s, err := NewOrderedStream(groupedConfig(), alertWriterFunc(func(*types.Alert) error { return nil }), "fixture")
		if err != nil {
			b.Fatal(err)
		}
		record := scopedTCP(1, "192.0.2.1")
		for range maxPendingRecords {
			if n, err := s.observe(record); err != nil || n != 0 {
				b.Fatal(n, err)
			}
		}
		if n, err := s.Finish(); err != nil || n != maxPendingRecords/50 {
			b.Fatal(n, err)
		}
	}
}

func BenchmarkOrderedStreamFutureRecords(b *testing.B) {
	for b.Loop() {
		s, err := NewOrderedStream(groupedConfig(), alertWriterFunc(func(*types.Alert) error { return nil }), "fixture")
		if err != nil {
			b.Fatal(err)
		}
		for i := range maxPendingRecords {
			if err := s.Push(scopedTCP(10000, "192.0.2.1")); err != nil {
				b.Fatal(err)
			}
			if n, err := s.Advance(int64(i + 1)); err != nil || n != 0 {
				b.Fatal(n, err)
			}
		}
		if n, err := s.Finish(); err != nil || n != maxPendingRecords/50 {
			b.Fatal(n, err)
		}
	}
}

func TestScopedApplicationAlertCannotLeakPayload(t *testing.T) {
	var got *types.Alert
	e, err := NewEngineFromConfig(&Config{Rules: []*Rule{{Name: "HTTP-observation", Type: "HTTP", Expression: "true", Enabled: true}}}, alertWriterFunc(func(a *types.Alert) error { got = a; return nil }))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = e.EvaluateScoped("scope", &types.HTTP{Timestamp: 1, URL: "https://fixture.invalid/?password=private-secret", RequestBody: []byte("private-secret")}); err != nil {
		t.Fatal(err)
	}
	if got == nil || strings.Contains(got.MatchedRecord, "private-secret") || got.MatchedRecordSHA256 == "" {
		t.Fatal("application secret entered scoped alert")
	}
}

func TestCaptureTimeConcurrentReloadAndEvaluation(t *testing.T) {
	cfg := groupedConfig()
	cfg.CaptureTime = &CaptureTimeConfig{Scope: "scope", LatenessSeconds: 10}
	e, err := NewEngineFromConfig(cfg, alertWriterFunc(func(*types.Alert) error { return nil }))
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 1; i <= 100; i++ {
			if _, err := e.Evaluate(scopedTCP(int64(i), "192.0.2.1")); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			if err := e.UpdateConfig(cfg); err != nil {
				t.Error(err)
				return
			}
			_ = e.GetStats()
		}
	}()
	wg.Wait()
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestOrderedWriteFailureIsTerminal(t *testing.T) {
	cfg := groupedConfig()
	cfg.Rules[0].Threshold = 2
	want := errors.New("synthetic persistence failure")
	attempts := 0
	s, err := NewOrderedStream(cfg, alertWriterFunc(func(*types.Alert) error { attempts++; return want }), "scope")
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 3; i++ {
		if err := s.Push(scopedTCP(int64(i), "192.0.2.1")); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 2; i++ {
		if _, err := s.Finish(); !errors.Is(err, want) {
			t.Fatal(err)
		}
		if s.pending != nil || s.bytes != 0 {
			t.Fatalf("terminal stream retained %d records and %d bytes", len(s.pending), s.bytes)
		}
	}
	if attempts != 1 {
		t.Fatal("failed crossing silently retried", attempts)
	}
}
