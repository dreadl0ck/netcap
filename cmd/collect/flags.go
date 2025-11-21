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

package collect

import (
	"github.com/urfave/cli/v3"

	"github.com/dreadl0ck/netcap/defaults"
)

// Global context for helper functions - defined in main.go
var currentMemBufferSize int

// Flags returns all flag names for the collect subcommand.
func Flags() []string {
	var flags []string
	for _, f := range GetFlags() {
		flags = append(flags, f.Names()[0])
	}
	return flags
}

// GetFlags returns the CLI flags for the collect subcommand.
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
			Name:    "gen-keypair",
			Usage:   "generate keypair",
			Sources: cli.EnvVars("NC_GEN_KEYPAIR"),
		},
		&cli.StringFlag{
			Name:    "privkey",
			Usage:   "path to the hex encoded server private key",
			Sources: cli.EnvVars("NC_PRIVKEY"),
		},
		&cli.StringFlag{
			Name:    "addr",
			Value:   "127.0.0.1:1335",
			Usage:   "specify an address and port to listen for incoming traffic",
			Sources: cli.EnvVars("NC_ADDR"),
		},
		&cli.IntFlag{
			Name:    "membuf-size",
			Value:   defaults.BufferSize,
			Usage:   "set size for membuf",
			Sources: cli.EnvVars("NC_MEMBUF_SIZE"),
		},
	}
}
