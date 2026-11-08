package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRuleNamesAreValidatedBeforeCompilationEvenWhenDisabled(t *testing.T) {
	for name, config := range map[string]*Config{
		"nil config": nil,
		"nil rule":   {Rules: []*Rule{nil}},
		"empty name": {Rules: []*Rule{{Name: ""}}},
		"whitespace": {Rules: []*Rule{{Name: " duplicate "}}},
		"duplicate":  {Rules: []*Rule{{Name: "duplicate", Type: "HTTP"}, {Name: "duplicate", Type: "DNS"}}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := CompileRules(config); err == nil {
				t.Fatal("invalid rule identity accepted")
			}
		})
	}
}

func TestDirectoryIdentityConflictsCannotFallBackToDefaultRules(t *testing.T) {
	directory := t.TempDir()
	for _, name := range []string{"one.yml", "two.yml"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte("rules:\n  - name: shared\n    type: TCP\n    expression: DstPort == 443\n    enabled: false\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, load := range []func(string) (*Config, error){LoadRulesFromDirectory, LoadRulesWithEmbeddedDefaults} {
		if _, err := load(directory); err == nil || !strings.Contains(err.Error(), "duplicate rule name") {
			t.Fatalf("invalid directory was hidden: %v", err)
		}
	}
	if _, err := LoadRulesWithEmbeddedDefaults(filepath.Join(directory, "missing")); err == nil {
		t.Fatal("missing configured directory was hidden")
	}
}
