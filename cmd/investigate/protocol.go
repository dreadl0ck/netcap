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
	return &cli.Command{Name: "protocol-server", Usage: "emulate one TCP/TLS or peer-pinned UDP session; fresh variables per invocation", Flags: []cli.Flag{&cli.StringFlag{Name: "spec", Required: true}, &cli.StringFlag{Name: "listen", Value: "127.0.0.1:0"}}, Action: func(ctx context.Context, cmd *cli.Command) error {
		if cmd.Args().Len() != 0 {
			return fmt.Errorf("no positional arguments supported")
		}
		var spec protocoltest.Exchange
		if err := readExperimentSpec(cmd.String("spec"), &spec); err != nil {
			return err
		}
		if err := spec.Validate(); err != nil {
			return err
		}
		if spec.Network == "udp" {
			p, err := net.ListenPacket("udp", cmd.String("listen"))
			if err != nil {
				return err
			}
			defer p.Close()
			if _, err = fmt.Fprintln(cmd.Root().ErrWriter, "Protocol UDP server listening on", p.LocalAddr()); err != nil {
				return err
			}
			r, runErr := protocoltest.ServeUDP(ctx, p, spec)
			if err = json.NewEncoder(cmd.Root().Writer).Encode(r); err != nil {
				return err
			}
			return runErr
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
	return &cli.Command{Name: "protocol-corpus", Usage: "versioned deterministic control/truncation/XOR corpus from contiguous directional bytes", Flags: []cli.Flag{&cli.StringFlag{Name: "target-version", Required: true}, &cli.StringFlag{Name: "read", Required: true}, &cli.IntFlag{Name: "max-cases", Value: 1024}, &cli.IntFlag{Name: "max-bytes", Value: 1 << 20}}, Action: func(ctx context.Context, cmd *cli.Command) error {
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
		r, err := protocoltest.GenerateByteCorpus(b, cmd.Int("max-cases"), cmd.Int("max-bytes"), cmd.String("target-version"))
		if err != nil {
			return err
		}
		return json.NewEncoder(cmd.Root().Writer).Encode(r)
	}}
}

func protocolGenerateCommand() *cli.Command {
	return &cli.Command{Name: "protocol-generate", Usage: "generate versioned grammar/field/setup-step cases from a campaign spec without network I/O", Flags: []cli.Flag{&cli.StringFlag{Name: "spec", Required: true}}, Action: func(ctx context.Context, cmd *cli.Command) error {
		if cmd.Args().Len() != 0 {
			return fmt.Errorf("no positional arguments supported")
		}
		var spec protocoltest.Campaign
		if err := readExperimentSpec(cmd.String("spec"), &spec); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		r, err := protocoltest.GenerateCampaign(spec)
		if err != nil {
			return err
		}
		return json.NewEncoder(cmd.Root().Writer).Encode(r)
	}}
}
func protocolReproduceCommand() *cli.Command {
	return &cli.Command{Name: "protocol-reproduce", Usage: "verify case hash, reset isolation and rerun exact generated/minimized exchange against its marker oracle", Flags: []cli.Flag{&cli.StringFlag{Name: "spec", Required: true}}, Action: func(ctx context.Context, cmd *cli.Command) error {
		if cmd.Args().Len() != 0 {
			return fmt.Errorf("no positional arguments supported")
		}
		var spec protocoltest.ReproductionSpec
		if err := readExperimentSpec(cmd.String("spec"), &spec); err != nil {
			return err
		}
		r, runErr := protocoltest.Reproduce(ctx, spec)
		if err := json.NewEncoder(cmd.Root().Writer).Encode(r); err != nil {
			return err
		}
		return runErr
	}}
}
func protocolTriageCommand() *cli.Command {
	return &cli.Command{Name: "protocol-triage", Usage: "import bounded external evidence verbatim; never infer RCE from a crash", Flags: []cli.Flag{&cli.StringFlag{Name: "input-generation", Required: true}, &cli.StringFlag{Name: "read", Required: true}, &cli.StringFlag{Name: "artifact", Required: true}, &cli.StringFlag{Name: "kind", Required: true}, &cli.StringFlag{Name: "target-version", Required: true}, &cli.StringFlag{Name: "reset", Required: true}}, Action: func(ctx context.Context, cmd *cli.Command) error {
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
		r, err := protocoltest.ImportGeneratedTriage(cmd.String("kind"), cmd.String("target-version"), cmd.String("reset"), cmd.String("input-generation"), b, cmd.String("artifact"))
		if err != nil {
			return err
		}
		return json.NewEncoder(cmd.Root().Writer).Encode(r)
	}}
}
