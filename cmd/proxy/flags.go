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

package proxy

import (
	"github.com/urfave/cli/v3"

	"github.com/dreadl0ck/netcap/defaults"
)

// Global context variables for helper functions
var (
	flagDebug            bool
	flagTrace            bool
	flagDump             bool
	flagDumpFormatted    bool
	flagDialTimeout      int
	flagMaxIdleConns     int
	flagIdleConnTimeout  int
	flagTLSHandshakeTimeout int
	flagSkipTLSVerify    bool
	flagMemBufferSize    int
)

// Flags returns all flag names for the proxy subcommand.
func Flags() []string {
	var flags []string
	for _, f := range GetFlags() {
		flags = append(flags, f.Names()[0])
	}
	return flags
}

// GetFlags returns the CLI flags for the proxy subcommand.
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
		&cli.IntFlag{
			Name:    "dialTimeout",
			Value:   30,
			Usage:   "seconds until dialing to the backend times out",
			Sources: cli.EnvVars("NC_DIALTIMEOUT"),
		},
		&cli.IntFlag{
			Name:    "idleConnTimeout",
			Value:   90,
			Usage:   "seconds until a connection times out",
			Sources: cli.EnvVars("NC_IDLECONNTIMEOUT"),
		},
		&cli.IntFlag{
			Name:    "tlsTimeout",
			Value:   15,
			Usage:   "seconds until a TLS handshake times out",
			Sources: cli.EnvVars("NC_TLSTIMEOUT"),
		},
		&cli.BoolFlag{
			Name:    "skipTlsVerify",
			Usage:   "skip TLS verification",
			Sources: cli.EnvVars("NC_SKIPTLSVERIFY"),
		},
		&cli.IntFlag{
			Name:    "maxIdle",
			Value:   120,
			Usage:   "maximum number of idle connections",
			Sources: cli.EnvVars("NC_MAXIDLE"),
		},
		&cli.StringFlag{
			Name:    "local",
			Usage:   "set local endpoint",
			Sources: cli.EnvVars("NC_LOCAL"),
		},
		&cli.StringFlag{
			Name:    "proxy-config",
			Value:   "net.proxy-config.yml",
			Usage:   "set config file path",
			Sources: cli.EnvVars("NC_PROXY_CONFIG"),
		},
		&cli.StringFlag{
			Name:    "remote",
			Usage:   "set remote endpoint",
			Sources: cli.EnvVars("NC_REMOTE"),
		},
		&cli.BoolFlag{
			Name:    "debug",
			Usage:   "set debug mode",
			Sources: cli.EnvVars("NC_DEBUG"),
		},
		&cli.BoolFlag{
			Name:    "trace",
			Value:   true,
			Usage:   "trace HTTP requests to retrieve additional information",
			Sources: cli.EnvVars("NC_TRACE"),
		},
		&cli.BoolFlag{
			Name:    "dump",
			Usage:   "dumps audit record as JSON to stdout",
			Sources: cli.EnvVars("NC_DUMP"),
		},
		&cli.BoolFlag{
			Name:    "format",
			Value:   true,
			Usage:   "format when dumping JSON",
			Sources: cli.EnvVars("NC_FORMAT"),
		},
		&cli.IntFlag{
			Name:    "membuf-size",
			Value:   defaults.BufferSize,
			Usage:   "set size for membuf",
			Sources: cli.EnvVars("NC_MEMBUF_SIZE"),
		},
	}
}
