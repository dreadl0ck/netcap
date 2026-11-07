package firewall

import (
	"context"
	"encoding/json"
	"os"

	"github.com/dreadl0ck/netcap/internal/appliance"
	"github.com/dreadl0ck/netcap/internal/firewallauth"
	"github.com/urfave/cli/v3"
)

func applianceCommand() *cli.Command {
	c := &cli.Command{Name: "appliance", Usage: "operator-owned named topology lifecycle (JSON output)"}
	for _, action := range []string{"plan", "apply", "recover", "remove", "status"} {
		c.Commands = append(c.Commands, &cli.Command{Name: action, Flags: []cli.Flag{
			&cli.StringFlag{Name: "manifest", Required: true},
			&cli.StringFlag{Name: "state-dir", Value: "/var/lib/netcap-appliance"},
			&cli.BoolFlag{Name: "dry-run"},
			&cli.StringFlag{Name: "auth-config"},
			&cli.StringFlag{Name: "operator-token-env"},
			&cli.StringFlag{Name: "reviewed-plan-digest"},
			&cli.StringFlag{Name: "approval-receipt-env"},
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
				if m.Mode == "production" {
					a, f, e := loadAuth(c.String("auth-config"))
					if e != nil {
						return e
					}
					if a == nil {
						return firewallauth.ErrUnauthenticated
					}
					defer a.Close()
					token, e := envToken(c.String("operator-token-env"))
					if e != nil {
						return e
					}
					p, e := a.Authenticate(ctx, token)
					if e != nil {
						return e
					}
					var receipt string
					if name := c.String("approval-receipt-env"); name != "" {
						if !envName.MatchString(name) {
							return firewallauth.ErrForbidden
						}
						receipt = os.Getenv(name)
					}
					ctx = appliance.WithBootstrap(firewallauth.WithPrincipal(ctx, p), appliance.Bootstrap{Scope: f.Scope, ReviewedDigest: c.String("reviewed-plan-digest"), Approvals: f.approvals, Receipt: receipt})
				}
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
