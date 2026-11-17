package webui

import (
	"path/filepath"
	"testing"

	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/internal/rules"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
)

func TestQueuedJobOwnsDetectionConfiguration(t *testing.T) {
	dir := t.TempDir()
	s := &Server{outDir: dir, rulesConfig: &rules.Config{Rules: []*rules.Rule{{Name: "admitted", Type: "HTTP", Expression: `Method == "GET"`, Enabled: true}}}}
	config, err := s.loadRulesConfig()
	if err != nil {
		t.Fatal(err)
	}
	config.Rules[0].Expression = "false"
	unchanged, err := s.loadRulesConfig()
	if err != nil || unchanged.Rules[0].Expression != `Method == "GET"` {
		t.Fatal("rule editor mutated shared cache", err)
	}
	snapshot, err := s.snapshotJobSettings()
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.cleanup()
	if snapshot.Runtime.MaxRetainedTCPBytes != defaults.MaxRetainedTCPBytes || snapshot.Runtime.MaxRetainedReassemblyBytes != defaults.MaxRetainedReassemblyBytes || snapshot.Runtime.MaxRetainedTCPStateBytes != defaults.MaxRetainedTCPStateBytes || snapshot.Runtime.MaxAggregateStateBytes != defaults.MaxAggregateStateBytes {
		t.Fatal("fallback runtime budgets diverged", snapshot.Runtime)
	}
	writeTimelineAuditFile(t, dir, "HTTP", types.Type(types.Type_value["NC_HTTP"]), []proto.Message{&types.HTTP{Method: "GET", Timestamp: 1}})
	s.rulesConfigMutex.Lock()
	s.rulesConfig = &rules.Config{Rules: []*rules.Rule{{Name: "changed", Type: "HTTP", Expression: "false", Enabled: true}}}
	s.rulesConfigMutex.Unlock()
	job := &AnalysisJob{SessionID: "snapshot", OutputDir: dir, settings: snapshot}
	if err := s.executeRulesForJob(job); err != nil {
		t.Fatal(err)
	}
	alerts, err := s.readAlertsFromFile(filepath.Join(dir, "Alert.ncap.gz"))
	if err != nil || len(alerts) != 1 || alerts[0].RuleName != "admitted" {
		t.Fatal("queued rule generation changed", alerts, err)
	}
}
