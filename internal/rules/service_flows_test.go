package rules

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/types"
)

func TestAlertTuningHuntsCompileWhenEnabled(t *testing.T) {
	config, err := LoadRulesFromFile(filepath.Join("examples", "alert_tuning_hunts.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range config.Rules {
		if rule.Enabled {
			t.Fatalf("unvalidated hunt %q should be opt-in", rule.Name)
		}
		rule.Enabled = true
	}
	if err := CompileRules(config); err != nil {
		t.Fatal(err)
	}
}

func TestAdClickBurstUsesClientAndWindow(t *testing.T) {
	config, err := LoadRulesFromFile(filepath.Join("examples", "alert_tuning_hunts.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range config.Rules {
		rule.Enabled = rule.Name == "HTTP Advertising Click Burst"
	}
	var alerts []*types.Alert
	replay, err := NewAuditReplay(config, alertWriterFunc(func(a *types.Alert) error { alerts = append(alerts, a); return nil }))
	if err != nil {
		t.Fatal(err)
	}
	for i := range 30 {
		for _, record := range []*types.HTTP{
			{SrcIP: "192.0.2.1", Host: "ads.doubleclick.net", URL: "/pagead/aclk?q=fixture", Referer: "https://ads.doubleclick.net/", Method: "GET"},
			{SrcIP: "192.0.2.2", Host: "ads.doubleclick.net", URL: "/pixel", Referer: "https://ads.doubleclick.net/", Method: "GET"},
			{SrcIP: "192.0.2.3", Host: "ads.doubleclick.net.example", URL: "/pagead/aclk?q=fixture", Referer: "https://ads.doubleclick.net/", Method: "GET"},
		} {
			record.Timestamp = time.Unix(1700000000+int64(i), 0).UnixNano()
			if _, err := replay.Evaluate(record); err != nil {
				t.Fatal(err)
			}
		}
	}
	if len(alerts) != 1 || alerts[0].SrcIP != "192.0.2.1" || alerts[0].Count != 30 {
		t.Fatalf("unqualified click burst: %v", alerts)
	}
}

func TestRDPServiceRulesRequireAcceptedNegotiation(t *testing.T) {
	config, err := LoadEmbeddedRules()
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range config.Rules {
		rule.Enabled = rule.Enabled && (rule.Name == "RDP External Connection" || rule.Name == "RDP Detected")
	}
	var alerts []*types.Alert
	replay, err := NewAuditReplay(config, alertWriterFunc(func(a *types.Alert) error { alerts = append(alerts, a); return nil }))
	if err != nil {
		t.Fatal(err)
	}
	for _, outcome := range []string{"malformed", "not-observed", "rejected", "accepted", "accepted"} {
		if _, err := replay.Evaluate(&types.RDP{Timestamp: 1000, SrcIP: "10.0.0.2", DstIP: "8.8.8.8", DstPort: 3389, NegotiationOutcome: outcome}); err != nil {
			t.Fatal(err)
		}
	}
	if len(alerts) != 1 || alerts[0].RuleName != "RDP External Connection" || alerts[0].Severity != "medium" {
		t.Fatalf("external RDP negotiation: %v", alerts)
	}
}

func TestServiceRuleUsesConnectionEvidence(t *testing.T) {
	config, err := LoadEmbeddedRules()
	if err != nil {
		t.Fatal(err)
	}
	var ssh *Rule
	for _, rule := range config.Rules {
		if rule.Name == "SSH Connection Detected" {
			ssh = rule
		}
	}
	if ssh == nil || ssh.Type != "Connection" {
		t.Fatalf("expected a Connection rule, got %+v", ssh)
	}
	replay, err := NewAuditReplay(&Config{Rules: []*Rule{ssh}}, alertWriterFunc(func(*types.Alert) error { return nil }))
	if err != nil {
		t.Fatal(err)
	}
	for i, tc := range []struct {
		id      string
		payload int32
		want    int
	}{
		{"probe", 0, 0}, {"first-session", 8, 1}, {"first-session", 16, 0}, {"second-session", 8, 1}, {"", 8, 1},
	} {
		got, err := replay.Evaluate(&types.Connection{
			TransportProto: "TCP", SrcIP: "192.0.2.1", DstIP: "192.0.2.2", SrcPort: "41000", DstPort: "22",
			TimestampFirst: int64(i + 1), ObservationID: tc.id, PacketsClientToServer: 2, PacketsServerToClient: 1, AppPayloadSize: tc.payload,
		})
		if err != nil || got != tc.want {
			t.Errorf("observation %q (%d bytes): %d alerts, %v; want %d", tc.id, tc.payload, got, err, tc.want)
		}
	}
	if got, err := replay.Evaluate(&types.Connection{TransportProto: "TCP", SrcIP: "192.0.2.2", DstIP: "192.0.2.1", SrcPort: "110", DstPort: "22",
		TimestampFirst: 50, CounterSemantics: "tuple-cumulative", Established: true}); err != nil || got != 0 {
		t.Fatalf("reply-first ephemeral port was reported as SSH: %d, %v", got, err)
	}
}
