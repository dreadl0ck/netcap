package investigate

import (
	"context"
	"encoding/json"
	"fmt"
	"net"

	"github.com/dreadl0ck/netcap/internal/protocoltest"
	"github.com/urfave/cli/v3"
)

func protocolCampaignCommand() *cli.Command {
	return &cli.Command{Name: "protocol-fuzz", Usage: "bounded deterministic mutations and deletion minimization with valid controls and explicit response marker", Flags: []cli.Flag{&cli.StringFlag{Name: "spec", Required: true}}, Action: func(ctx context.Context, cmd *cli.Command) error {
		if cmd.Args().Len() != 0 {
			return fmt.Errorf("no positional arguments supported")
		}
		var spec protocoltest.Campaign
		if err := readExperimentSpec(cmd.String("spec"), &spec); err != nil {
			return err
		}
		r, runErr := protocoltest.RunCampaign(ctx, spec)
		if err := json.NewEncoder(cmd.Root().Writer).Encode(r); err != nil {
			return err
		}
		return runErr
	}}
}

func protocolServerCommand() *cli.Command {
	return &cli.Command{Name: "protocol-server", Usage: "emulate one ordered plaintext TCP session; fresh variables per invocation", Flags: []cli.Flag{&cli.StringFlag{Name: "spec", Required: true}, &cli.StringFlag{Name: "listen", Value: "127.0.0.1:0"}}, Action: func(ctx context.Context, cmd *cli.Command) error {
		if cmd.Args().Len() != 0 {
			return fmt.Errorf("no positional arguments supported")
		}
		var spec protocoltest.Exchange
		if err := readExperimentSpec(cmd.String("spec"), &spec); err != nil {
			return err
		}
		l, err := net.Listen("tcp", cmd.String("listen"))
		if err != nil {
			return err
		}
		defer l.Close()
		if _, err = fmt.Fprintln(cmd.Root().ErrWriter, "Protocol server listening on", l.Addr()); err != nil {
			return err
		}
		r, runErr := protocoltest.ServeOne(ctx, l, spec)
		if err = json.NewEncoder(cmd.Root().Writer).Encode(r); err != nil {
			return err
		}
		return runErr
	}}
}
func protocolAccessCommand() *cli.Command {
	return &cli.Command{Name: "protocol-access", Usage: "run bounded labeled state/role/resource cases with returned-marker evidence", Flags: []cli.Flag{&cli.StringFlag{Name: "spec", Required: true}}, Action: func(ctx context.Context, cmd *cli.Command) error {
		if cmd.Args().Len() != 0 {
			return fmt.Errorf("no positional arguments supported")
		}
		var cases []protocoltest.AccessCase
		if err := readExperimentSpec(cmd.String("spec"), &cases); err != nil {
			return err
		}
		r, runErr := protocoltest.RunAccess(ctx, cases)
		if err := json.NewEncoder(cmd.Root().Writer).Encode(r); err != nil {
			return err
		}
		return runErr
	}}
}
func protocolCorpusCommand() *cli.Command {
	return &cli.Command{Name: "protocol-corpus", Usage: "deterministic control/truncation/XOR corpus from contiguous directional bytes", Flags: []cli.Flag{&cli.StringFlag{Name: "read", Required: true}, &cli.IntFlag{Name: "max-cases", Value: 1024}, &cli.IntFlag{Name: "max-bytes", Value: 1 << 20}}, Action: func(ctx context.Context, cmd *cli.Command) error {
		if cmd.Args().Len() != 0 {
			return fmt.Errorf("no positional arguments supported")
		}
		b, err := protocoltest.ReadDirectionalInput(cmd.String("read"))
		if err != nil {
			return err
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		r, err := protocoltest.MutationCorpus(b, cmd.Int("max-cases"), cmd.Int("max-bytes"))
		if err != nil {
			return err
		}
		return json.NewEncoder(cmd.Root().Writer).Encode(r)
	}}
}
func protocolTriageCommand() *cli.Command {
	return &cli.Command{Name: "protocol-triage", Usage: "import bounded external evidence verbatim; never infer RCE from a crash", Flags: []cli.Flag{&cli.StringFlag{Name: "read", Required: true}, &cli.StringFlag{Name: "artifact", Required: true}, &cli.StringFlag{Name: "kind", Required: true}, &cli.StringFlag{Name: "target-version", Required: true}, &cli.StringFlag{Name: "reset", Required: true}}, Action: func(ctx context.Context, cmd *cli.Command) error {
		if cmd.Args().Len() != 0 {
			return fmt.Errorf("no positional arguments supported")
		}
		b, err := protocoltest.ReadDirectionalInput(cmd.String("read"))
		if err != nil {
			return err
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		r, err := protocoltest.ImportTriage(cmd.String("kind"), cmd.String("target-version"), cmd.String("reset"), b, cmd.String("artifact"))
		if err != nil {
			return err
		}
		return json.NewEncoder(cmd.Root().Writer).Encode(r)
	}}
}
