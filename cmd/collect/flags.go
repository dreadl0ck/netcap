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
