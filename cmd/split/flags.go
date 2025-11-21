package split

import (
	"github.com/urfave/cli/v3"
)

// Flags returns all flag names for the split subcommand.
func Flags() []string {
	var flags []string
	for _, f := range GetFlags() {
		flags = append(flags, f.Names()[0])
	}
	return flags
}

// GetFlags returns the CLI flags for the split subcommand.
func GetFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:    "read",
			Usage:   "input pcap file",
			Sources: cli.EnvVars("NC_READ"),
		},
	}
}

