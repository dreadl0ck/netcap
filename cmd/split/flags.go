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
		&cli.StringFlag{Name: "out", Usage: "new private output directory (must not exist)"},
		&cli.StringFlag{Name: "bpf", Usage: "exact libpcap BPF selection, e.g. host 192.0.2.1 or a paired TCP tuple"},
		&cli.StringFlag{Name: "start-ns", Usage: "inclusive Unix nanosecond start (decimal integer)"},
		&cli.StringFlag{Name: "end-ns", Usage: "inclusive Unix nanosecond end (decimal integer)"},
		&cli.StringFlag{Name: "source-sha256", Usage: "expected SHA256 of original capture; mismatch discards output"},
		&cli.IntFlag{Name: "max-packets", Value: 1_000_000, Usage: "fail rather than truncate above this selected-packet count"},
		&cli.Int64Flag{Name: "max-bytes", Value: 256 << 20, Usage: "fail rather than truncate above this PCAPNG output size"},
		&cli.StringFlag{
			Name:    "read",
			Usage:   "input pcap file",
			Sources: cli.EnvVars("NC_READ"),
		},
	}
}
