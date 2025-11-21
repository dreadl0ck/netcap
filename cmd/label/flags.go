/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017-2020 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package label

import (
	"github.com/urfave/cli/v3"
)

// Flags returns all flag names for the label subcommand.
func Flags() []string {
	var flags []string
	for _, f := range GetFlags() {
		flags = append(flags, f.Names()[0])
	}
	return flags
}

// GetFlags returns the CLI flags for the label subcommand.
func GetFlags() []cli.Flag {
	return []cli.Flag{
		&cli.BoolFlag{
			Name:    "gen-config",
			Usage:   "generate config",
			Sources: cli.EnvVars("NC_GEN_CONFIG"),
		},
		&cli.StringFlag{
			Name:    "config",
			Usage:   "read configuration from file at path",
			Sources: cli.EnvVars("NC_CONFIG"),
		},
		&cli.BoolFlag{
			Name:    "debug",
			Usage:   "toggle debug mode",
			Sources: cli.EnvVars("NC_DEBUG"),
		},
		&cli.StringFlag{
			Name:    "read",
			Usage:   "use specified pcap file to scan with suricata",
			Sources: cli.EnvVars("NC_READ"),
		},
		&cli.StringFlag{
			Name:    "sep",
			Value:   ",",
			Usage:   "set separator string for csv output",
			Sources: cli.EnvVars("NC_SEP"),
		},
		&cli.StringFlag{
			Name:    "out",
			Usage:   "specify output directory, will be created if it does not exist",
			Sources: cli.EnvVars("NC_OUT"),
		},
		&cli.BoolFlag{
			Name:    "description",
			Usage:   "use attack description instead of classification for labels",
			Sources: cli.EnvVars("NC_DESCRIPTION"),
		},
		&cli.BoolFlag{
			Name:    "progress",
			Usage:   "use progress bars",
			Sources: cli.EnvVars("NC_PROGRESS"),
		},
		&cli.BoolFlag{
			Name:    "strict",
			Usage:   "fail when there is more than one alert for the same timestamp",
			Sources: cli.EnvVars("NC_STRICT"),
		},
		&cli.StringFlag{
			Name:    "exclude",
			Usage:   "specify a comma separated list of suricata classifications that shall be excluded from the generated labeled csv",
			Sources: cli.EnvVars("NC_EXCLUDE"),
		},
		&cli.BoolFlag{
			Name:    "collect",
			Usage:   "append classifications from alert with duplicate timestamps to the generated label",
			Sources: cli.EnvVars("NC_COLLECT"),
		},
		&cli.BoolFlag{
			Name:    "disable-layers",
			Usage:   "do not map layer types by timestamp",
			Sources: cli.EnvVars("NC_DISABLE_LAYERS"),
		},
		&cli.StringFlag{
			Name:    "suricata-config",
			Value:   "/usr/local/etc/suricata/suricata.yaml",
			Usage:   "set the path to the suricata config file",
			Sources: cli.EnvVars("NC_SURICATA_CONFIG"),
		},
		&cli.StringFlag{
			Name:    "custom",
			Usage:   "use custom mappings at path",
			Sources: cli.EnvVars("NC_CUSTOM"),
		},
	}
}
