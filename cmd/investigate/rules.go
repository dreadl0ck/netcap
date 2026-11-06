package investigate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/dreadl0ck/netcap/internal/rules"
	"github.com/urfave/cli/v3"
)

func offlineRulesCommand() *cli.Command {
	return &cli.Command{
		Name: "rules", Usage: "evaluate grouped thresholds on finalized saved audit records (alerts only)",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "read", Required: true, Usage: "finalized capture output directory with audit-output-ready.json"},
			&cli.StringFlag{Name: "rules", Required: true, Usage: "netcap-offline-rules/v1 YAML pack"},
		},
		Action: runOfflineRules,
	}
}

func runOfflineRules(ctx context.Context, cmd *cli.Command) error {
	if cmd.Args().Len() != 0 {
		return fmt.Errorf("investigate rules does not accept positional arguments")
	}
	pack, err := rules.LoadOfflinePack(cmd.String("rules"))
	if err != nil {
		return fmt.Errorf("offline rules: %w", err)
	}
	report, evaluationErr := rules.EvaluateOffline(ctx, rules.OfflineRequest{Directory: cmd.String("read"), Pack: pack})
	if report != nil {
		encoder := json.NewEncoder(cmd.Root().Writer)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(report); err != nil {
			return errors.Join(evaluationErr, err)
		}
	}
	if evaluationErr != nil {
		return fmt.Errorf("offline rules: %w", evaluationErr)
	}
	if report == nil || report.Status != "complete" {
		return fmt.Errorf("offline rules: incomplete coverage; inspect the execution report")
	}
	return nil
}
