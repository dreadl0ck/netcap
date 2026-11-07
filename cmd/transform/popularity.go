package transform

import (
	"context"
	"fmt"
	"github.com/dreadl0ck/netcap/internal/resolvers"
	"github.com/urfave/cli/v3"
	"os"
)

func GetFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{Name: "domain-popularity-list", Usage: "optional local popularity CSV outside managed dbs (default off)"},
		&cli.StringFlag{Name: "domain-popularity-format", Value: "rank-domain", Usage: "rank-domain (Tranco, no header), netapi (NetAPI_Rank,Domain header), majestic (12-column header)"},
	}
}

func RunWithContext(_ context.Context, cmd *cli.Command) error {
	path, format := cmd.String("domain-popularity-list"), cmd.String("domain-popularity-format")
	if err := resolvers.ValidatePopularityFormat(format); err != nil {
		return err
	}
	if path != "" {
		if _, stats, err := resolvers.LoadDomainPopularityList(path, format, resolvers.DataBaseFolderPath); err != nil {
			return fmt.Errorf("domain popularity: %+v: %w", stats, err)
		}
	}
	resolvers.CurrentConfig.DomainPopularityList = path
	resolvers.CurrentConfig.DomainPopularityFormat = format
	// Legacy Maltego helpers consume fixed positional arguments from os.Args.
	original := os.Args
	os.Args = append([]string{original[0], "transform"}, cmd.Args().Slice()...)
	defer func() { os.Args = original }()
	Run()
	return nil
}
