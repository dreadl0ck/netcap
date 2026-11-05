package util

import (
	"bytes"
	"context"
	"github.com/urfave/cli/v3"
	"strings"
	"testing"
)

func TestEnvPrintsConfiguredOverrides(t *testing.T) {
	t.Setenv("NC_EVALUATION_FIXTURE", "configured")
	var output bytes.Buffer
	c := &cli.Command{Writer: &output, Flags: GetFlags(), Action: RunWithContext}
	if err := c.Run(context.Background(), []string{"util", "--env"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "NC_EVALUATION_FIXTURE=configured\n") {
		t.Fatal("environment override missing")
	}
}
