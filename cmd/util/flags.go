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

package util

import (
	"github.com/urfave/cli/v3"

	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/env"
)

// Flags returns all flag names for the util subcommand.
func Flags() []string {
	var flags []string
	for _, f := range GetFlags() {
		flags = append(flags, f.Names()[0])
	}
	return flags
}

// GetFlags returns the CLI flags for the util subcommand.
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
			Name:    "check",
			Usage:   "check number of occurrences of the separator, in fields of an audit record file",
			Sources: cli.EnvVars("NC_CHECK"),
		},
		&cli.StringFlag{
			Name:    "ts2utc",
			Usage:   "util to convert seconds.microseconds timestamp to UTC",
			Sources: cli.EnvVars("NC_TS2UTC"),
		},
		&cli.StringFlag{
			Name:    "read",
			Usage:   "read specified audit record file",
			Sources: cli.EnvVars("NC_READ"),
		},
		&cli.StringFlag{
			Name:    "sep",
			Value:   ",",
			Usage:   "set separator string for csv output",
			Sources: cli.EnvVars("NC_SEP"),
		},
		&cli.BoolFlag{
			Name:    "generate-dbs",
			Usage:   "fetch and generate netcap-dbs and exit",
			Sources: cli.EnvVars("NC_GENERATE_DBS"),
		},
		&cli.BoolFlag{
			Name:    "update-dbs",
			Usage:   "update the current databases to the latest version and exit",
			Sources: cli.EnvVars("NC_UPDATE_DBS"),
		},
		&cli.IntFlag{
			Name:    "membuf-size",
			Value:   defaults.BufferSize,
			Usage:   "set size for membuf",
			Sources: cli.EnvVars("NC_MEMBUF_SIZE"),
		},
		&cli.BoolFlag{
			Name:    "env",
			Usage:   "print netcap environment variables and exit",
			Sources: cli.EnvVars("NC_ENV"),
		},
		&cli.BoolFlag{
			Name:    "interfaces",
			Usage:   "print network interfaces and exit",
			Sources: cli.EnvVars("NC_INTERFACES"),
		},
		&cli.StringFlag{
			Name:    "index",
			Usage:   "index data for full text search",
			Sources: cli.EnvVars("NC_INDEX"),
		},
		&cli.StringFlag{
			Name:    "mkpacket",
			Usage:   "create a TCP or UDP packet with piped input from stdin",
			Sources: cli.EnvVars("NC_MKPACKET"),
		},
		&cli.IntFlag{
			Name:    "nvd-start-year",
			Value:   2002,
			Usage:   "year to start indexing the nvd dbs from",
			Sources: cli.EnvVars("NC_NVD_START_YEAR"),
		},
		&cli.BoolFlag{
			Name:    "force",
			Usage:   "disable prompts for user interaction",
			Sources: cli.EnvVars("NC_FORCE"),
		},
		&cli.BoolFlag{
			Name:    "verbose",
			Usage:   "enable verbose output",
			Sources: cli.EnvVars("NC_VERBOSE"),
		},
		&cli.BoolFlag{
			Name:    "download-geolite",
			Usage:   "download geolite DB, requires API key in environment: " + env.GeoLiteAPIKey,
			Sources: cli.EnvVars("NC_DOWNLOAD_GEOLITE"),
		},
		&cli.BoolFlag{
			Name:    "serve-dbs",
			Usage:   "start HTTP server to serve databases with nightly rebuilds",
			Sources: cli.EnvVars("NC_SERVE_DBS"),
		},
		&cli.StringFlag{
			Name:    "serve-addr",
			Value:   ":8080",
			Usage:   "address for database server",
			Sources: cli.EnvVars("NC_SERVE_ADDR"),
		},
		&cli.BoolFlag{
			Name:    "download-dbs",
			Usage:   "download databases from remote server",
			Sources: cli.EnvVars("NC_DOWNLOAD_DBS"),
		},
		&cli.StringFlag{
			Name:    "dbs-url",
			Usage:   "URL to download databases from (default: " + env.NetcapDBsURL + ")",
			Sources: cli.EnvVars("NC_DBS_URL"),
		},
		&cli.BoolFlag{
			Name:    "decoders",
			Usage:   "display tree view of all supported audit record types and their encapsulation levels",
			Sources: cli.EnvVars("NC_DECODERS"),
		},
		&cli.BoolFlag{
			Name:    "gopacket-coverage",
			Usage:   "analyze gopacket layer type coverage and show unused layer types",
			Sources: cli.EnvVars("NC_GOPACKET_COVERAGE"),
		},
	}
}
