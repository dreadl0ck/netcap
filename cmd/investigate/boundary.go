package investigate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/dreadl0ck/netcap/internal/protocoltest"
	"github.com/urfave/cli/v3"
)

func protocolBoundaryCommand() *cli.Command {
	return &cli.Command{Name: "protocol-boundary", Usage: "distinguish exact target acceptance/rejection from harness stops; retain controls and optional effect readback", Flags: []cli.Flag{&cli.StringFlag{Name: "spec", Required: true}}, Action: func(ctx context.Context, cmd *cli.Command) error {
		if cmd.Args().Len() != 0 {
			return fmt.Errorf("no positional arguments supported")
		}
		var spec protocoltest.BoundaryCase
		if err := readExperimentSpec(cmd.String("spec"), &spec); err != nil {
			return err
		}
		r, err := protocoltest.RunBoundary(ctx, spec)
		return errors.Join(err, json.NewEncoder(cmd.Root().Writer).Encode(r))
	}}
}
