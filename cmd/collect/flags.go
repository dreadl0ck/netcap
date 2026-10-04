/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package collect

import (
	"time"

	"github.com/urfave/cli/v3"

	"github.com/dreadl0ck/netcap/internal/distributed"
)

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
			Name:    "gen-keypair",
			Usage:   "write a new collector certificate and key to -cert and -key, print its fingerprint and exit",
			Sources: cli.EnvVars("NC_GEN_KEYPAIR"),
		},
		&cli.StringFlag{
			Name:    "cert",
			Value:   "collector.crt",
			Usage:   "path to the collector certificate (PEM)",
			Sources: cli.EnvVars("NC_CERT"),
		},
		&cli.StringFlag{
			Name:    "key",
			Value:   "collector.key",
			Usage:   "path to the collector private key (PEM)",
			Sources: cli.EnvVars("NC_KEY"),
		},
		&cli.StringFlag{
			Name:    "clients",
			Usage:   "allowlist file, one \"<agent fingerprint> <name>\" per line; the name becomes the output directory",
			Sources: cli.EnvVars("NC_CLIENTS"),
		},
		&cli.StringFlag{
			Name:    "addr",
			Value:   "127.0.0.1:1335",
			Usage:   "TCP address to listen on",
			Sources: cli.EnvVars("NC_ADDR"),
		},
		&cli.StringFlag{
			Name:    "out",
			Value:   "collected",
			Usage:   "output directory; files go to <out>/<client name>/<Type>.ncap.gz",
			Sources: cli.EnvVars("NC_OUT"),
		},
		&cli.IntFlag{
			Name:    "max-frame",
			Value:   distributed.DefaultMaxFrame,
			Usage:   "largest accepted frame in bytes",
			Sources: cli.EnvVars("NC_MAX_FRAME"),
		},
		&cli.IntFlag{
			Name:    "max-conns",
			Value:   256,
			Usage:   "maximum concurrent agent connections",
			Sources: cli.EnvVars("NC_MAX_CONNS"),
		},
		&cli.DurationFlag{
			Name:    "idle-timeout",
			Value:   5 * time.Minute,
			Usage:   "close a connection that sends nothing for this long",
			Sources: cli.EnvVars("NC_IDLE_TIMEOUT"),
		},
		&cli.DurationFlag{
			Name:    "shutdown-timeout",
			Value:   30 * time.Second,
			Usage:   "how long to wait for in-flight batches on shutdown",
			Sources: cli.EnvVars("NC_SHUTDOWN_TIMEOUT"),
		},
	}
}
