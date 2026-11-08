package transform

import (
	"context"
	"github.com/dreadl0ck/netcap/internal/resolvers"
	"github.com/urfave/cli/v3"
	"os"
)

func GetFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{Name: "domain-popularity-list", Usage: "override managed NetAPI Top 1M with a local popularity CSV outside managed dbs"},
		&cli.BoolFlag{Name: "no-domain-popularity", Usage: "disable popularity suppression in filtered transforms"},
		&cli.StringFlag{Name: "domain-popularity-format", Value: "rank-domain", Usage: "rank-domain (Tranco, no header), netapi (NetAPI_Rank,Domain header), majestic (12-column header)"},
	}
}

func RunWithContext(_ context.Context, cmd *cli.Command) error {
	path, format := cmd.String("domain-popularity-list"), cmd.String("domain-popularity-format")
	if err := resolvers.ValidatePopularityFormat(format); err != nil {
		return err
	}
	resolvers.CurrentConfig.DomainPopularityList = path
	resolvers.CurrentConfig.DomainPopularityFormat = format
	resolvers.CurrentConfig.DisableDomainPopularity = cmd.Bool("no-domain-popularity")
	name := cmd.Args().First()
	if path != "" || name == "toHTTPHostsFiltered" || name == "toIncomingConnsFiltered" || name == "toOutgoingConnsFiltered" {
		if err := resolvers.InitDNSWhitelist(); err != nil {
			return err
		}
	}
	// Legacy Maltego helpers consume fixed positional arguments from os.Args.
	original := os.Args
	os.Args = append([]string{original[0], "transform"}, cmd.Args().Slice()...)
	defer func() { os.Args = original }()
	Run()
	return nil
}
