package util

import (
	"context"
	"strings"
	"testing"

	"github.com/urfave/cli/v3"
)

func TestPackDBsRequiresExplicitReviewedRecordsAndReturnsError(t *testing.T) {
	t.Setenv("NC_DBS_APPROVALS", "")
	cmd := &cli.Command{Name: "util", Flags: GetFlags(), Action: RunWithContext}
	err := cmd.Run(context.Background(), []string{"util", "--pack-dbs", t.TempDir(), "--dbs-output", t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "explicit reviewed records") {
		t.Fatalf("pack error not propagated: %v", err)
	}
}

func TestGenerateDBsRejectsInvalidRequiredYearWithoutAcquisition(t *testing.T) {
	cmd := &cli.Command{Name: "util", Flags: GetFlags(), Action: RunWithContext}
	err := cmd.Run(context.Background(), []string{"util", "--generate-dbs", "--nvd-start-year", "1"})
	if err == nil || !strings.Contains(err.Error(), "NVD start year") {
		t.Fatalf("generation error not propagated: %v", err)
	}
}
