package webui

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"gopkg.in/yaml.v2"

	"github.com/dreadl0ck/netcap/internal/rules"
)

// Saving or toggling a rule set rewrote each rule from a hand-picked field
// list that omitted group_by, so a grouped threshold became a global one.
func TestRuleSavesKeepGroupBy(t *testing.T) {
	root := t.TempDir()
	s := &Server{outDir: filepath.Join(root, "out")}
	grouped := func(name, set string) *rules.Rule {
		return &rules.Rule{Name: name, Type: "DNS", Expression: "true", Severity: "low", Enabled: true, Threshold: 100, ThresholdWindow: 600,
			GroupBy: []string{"SrcIP", "Questions.Name"}, Tags: []string{"embedded", "ruleset:" + set}}
	}
	if err := s.saveRulesConfig(&rules.Config{Rules: []*rules.Rule{grouped("set rule", "threshold_detections"), grouped("orphan", "")}}); err != nil {
		t.Fatal(err)
	}
	if err := s.saveRuleSetOverride("toggled", []*rules.Rule{grouped("toggled rule", "toggled")}); err != nil {
		t.Fatal(err)
	}
	folder := filepath.Join(root, "rules")
	entries, err := os.ReadDir(folder)
	if err != nil || len(entries) != 3 {
		t.Fatalf("saved files: %v %v", entries, err)
	}
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(folder, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var config rules.Config
		if err := yaml.Unmarshal(data, &config); err != nil || len(config.Rules) != 1 {
			t.Fatalf("%s: %v", entry.Name(), err)
		}
		if !slices.Equal(config.Rules[0].GroupBy, []string{"SrcIP", "Questions.Name"}) {
			t.Fatalf("%s lost group_by:\n%s", entry.Name(), data)
		}
	}
}
