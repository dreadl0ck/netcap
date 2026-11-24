package rules

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/types"
)

// Session-gated port rules fired once per data segment; the default dedup is
// per source and destination for five minutes of record time, so a long SMB
// session re-alerted every five minutes. dedupe_by alerts once per key.
func TestDedupeByAlertsOncePerKey(t *testing.T) {
	var alerts []*types.Alert
	config := &Config{Rules: []*Rule{
		{Name: "smb", Type: "TCP", Expression: "DstPort == 445 && ACK && PayloadSize > 0", Severity: "info", Enabled: true, DedupeBy: []string{"SrcIP", "DstIP", "DstPort"}},
		{Name: "windowed", Type: "TCP", Expression: "DstPort == 22 && ACK", Severity: "info", Enabled: true, DedupeBy: []string{"CommunityID"}, DedupeWindow: 60},
	}}
	replay, err := NewAuditReplay(config, alertWriterFunc(func(a *types.Alert) error { alerts = append(alerts, a); return nil }))
	if err != nil {
		t.Fatal(err)
	}
	base := int64(1_700_000_000) * int64(time.Second)
	feed := func(at time.Duration, src, dst string, port int32, community string) {
		t.Helper()
		if _, err := replay.Evaluate(&types.TCP{Timestamp: base + int64(at), SrcIP: src, DstIP: dst, DstPort: port, ACK: true, PayloadSize: 100, CommunityID: community}); err != nil {
			t.Fatal(err)
		}
	}
	for i := range 3000 {
		feed(time.Duration(i)*time.Second, "10.0.0.2", "10.0.0.10", 445, "")
	}
	feed(time.Hour, "10.0.0.3", "10.0.0.10", 445, "")
	count := func(rule string) (n int) {
		for _, a := range alerts {
			if a.RuleName == rule {
				n++
			}
		}
		return n
	}
	if count("smb") != 2 {
		t.Fatalf("smb alerts %d, want one per client", count("smb"))
	}
	feed(0, "10.0.0.2", "10.0.0.20", 22, "1:a")
	feed(30*time.Second, "10.0.0.2", "10.0.0.20", 22, "1:a")
	feed(90*time.Second, "10.0.0.2", "10.0.0.20", 22, "1:a")
	feed(91*time.Second, "10.0.0.2", "10.0.0.20", 22, "")
	if count("windowed") != 3 {
		t.Fatalf("windowed alerts %d: one per window, and records without the key are not deduplicated", count("windowed"))
	}
}

func TestDedupeByIsValidatedAndBounded(t *testing.T) {
	for _, rule := range []*Rule{
		{Name: "a", Type: "TCP", Expression: "SYN", Severity: "low", Enabled: true, DedupeBy: []string{"Nope"}},
		{Name: "b", Type: "TCP", Expression: "SYN", Severity: "low", Enabled: true, DedupeBy: []string{"SrcIP"}, Threshold: 5},
		{Name: "c", Type: "TCP", Expression: "SYN", Severity: "low", Enabled: true, DedupeWindow: 30},
	} {
		if err := CompileRules(&Config{Rules: []*Rule{rule}}); err == nil || !strings.Contains(err.Error(), "dedupe") {
			t.Errorf("%s compiled: %v", rule.Name, err)
		}
	}
	replay, err := NewAuditReplay(&Config{Rules: []*Rule{{Name: "r", Type: "TCP", Expression: "SYN", Severity: "low", Enabled: true, DedupeBy: []string{"DstIP"}}}}, alertWriterFunc(func(*types.Alert) error { return nil }))
	if err != nil {
		t.Fatal(err)
	}
	for i := range maxDedupeKeys + 50 {
		if _, err := replay.Evaluate(&types.TCP{Timestamp: int64(i + 1), DstIP: fmt.Sprint(i), SYN: true}); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(replay.engine.dedupe["r"].seen); n > maxDedupeKeys {
		t.Fatalf("dedupe state %d keys", n)
	}
}
