package rules

import "testing"

func TestIOCRulesCompile(t *testing.T) {
	config, err := LoadEmbeddedRules()
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, rule := range config.Rules {
		for _, tag := range rule.Tags {
			if tag == "ruleset:ioc_lists" {
				if rule.Enabled {
					t.Errorf("%s is enabled without a feed", rule.Name)
				}
				rule.Enabled = true
				count++
			}
		}
	}
	if count != 5 {
		t.Fatalf("loaded %d IOC examples, want 5", count)
	}
	if err := CompileRules(config); err != nil {
		t.Fatal(err)
	}
}
