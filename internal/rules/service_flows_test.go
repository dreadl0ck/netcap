package rules

import (
	"path/filepath"
	"testing"

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
}
