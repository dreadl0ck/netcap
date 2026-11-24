package webui

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/dreadl0ck/netcap/internal/rules"
)

func TestServiceRulesRequireExplicitPackAndMatchingBase(t *testing.T) {
	folder := t.TempDir()
	base := &rules.Config{Rules: []*rules.Rule{{Name: "Shipped", Enabled: true, Expression: "ACK"}}}
	pack := func(digest string) {
		t.Helper()
		config := "base_sha256: " + digest + "\ncustom:\n  - {name: Local, expression: ACK}\noverrides:\n  - {name: Shipped, expression: SYN}\n  - {name: Retired, expression: SYN}\n"
		if err := os.WriteFile(filepath.Join(folder, "operator.pack.yml"), []byte(config), 0600); err != nil {
			t.Fatal(err)
		}
	}
	pack("stale")
	for _, tc := range []struct {
		mode, baseDigest, expression string
		count                        int
	}{
		{"", "stale", "ACK", 1}, {"operator", "stale", "ACK", 2}, {"operator", ruleDigest(base), "SYN", 2},
	} {
		t.Setenv("NC_SERVICE_RULES_MODE", tc.mode)
		pack(tc.baseDigest)
		result, err := loadServiceRules(folder, base)
		if err != nil || len(result.Rules) != tc.count || result.Rules[0].Expression != tc.expression {
			t.Fatalf("mode=%q base=%q: %v, %v", tc.mode, tc.baseDigest, result, err)
		}
	}
}
