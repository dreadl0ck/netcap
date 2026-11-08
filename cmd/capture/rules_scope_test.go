package capture

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/urfave/cli/v3"
)

func TestCaptureTimeRulesRefuseMultipleInputs(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("NC_CONFIG_ROOT", filepath.Join(dir, "config"))
	for _, name := range []string{"a.pcap", "b.pcap"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	rulePath := filepath.Join(dir, "rules.yml")
	if err := os.WriteFile(rulePath, []byte("capture_time:\n  scope: declared-global\n  lateness_seconds: 60\nrules:\n  - name: test\n    type: TCP\n    expression: SYN\n    enabled: true\n    threshold: 2\n    group_by: [SrcIP]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := &cli.Command{Flags: GetFlags(), Action: RunWithContext}
	err := cmd.Run(context.Background(), []string{"capture", "--read", filepath.Join(dir, "*.pcap"), "--out", filepath.Join(dir, "out"), "--rules", rulePath, "--http", ""})
	if err == nil || !strings.Contains(err.Error(), "one qualified input source") {
		t.Fatalf("multiple inputs accepted or wrong failure: %v", err)
	}
}
