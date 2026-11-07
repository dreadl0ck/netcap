package firewall

import (
	"context"
	"encoding/json"

	"github.com/dreadl0ck/netcap/internal/appliance"
	"github.com/urfave/cli/v3"
)

func applianceCommand() *cli.Command {
	c := &cli.Command{Name: "appliance", Usage: "operator-owned isolated lab topology lifecycle (JSON output)"}
	for _, action := range []string{"plan", "apply", "recover", "remove", "status"} {
		c.Commands = append(c.Commands, &cli.Command{Name: action, Flags: []cli.Flag{
			&cli.StringFlag{Name: "manifest", Required: true},
			&cli.StringFlag{Name: "state-dir", Value: "/var/lib/netcap-appliance"},
			&cli.BoolFlag{Name: "dry-run"},
		}, Action: func(ctx context.Context, c *cli.Command) error {
			b, err := readBounded(c.String("manifest"), appliance.MaxManifestBytes)
			if err != nil {
				return err
			}
			m, err := appliance.Parse(b)
			if err != nil {
				return err
			}
			var result any
			if c.Name == "plan" || c.Bool("dry-run") {
				result, err = m.Plan()
			} else {
				result, err = appliance.Execute(ctx, m, c.String("state-dir"), c.Name)
			}
			if err != nil {
				return err
			}
			return json.NewEncoder(c.Root().Writer).Encode(result)
		}})
	}
	return c
}
