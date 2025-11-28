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

package dump

import (
	"github.com/urfave/cli/v3"

	"github.com/dreadl0ck/netcap/defaults"
)

// Flags returns all flags for the dump subcommand.
func Flags() []string {
	var flags []string
	for _, f := range GetFlags() {
		flags = append(flags, f.Names()[0])
	}
	return flags
}

// GetFlags returns the CLI flags for the dump subcommand.
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
		&cli.StringFlag{
			Name:    "select",
			Usage:   "select specific fields of an audit records when generating csv or tables",
			Sources: cli.EnvVars("NC_SELECT"),
		},
		&cli.BoolFlag{
			Name:    "fields",
			Usage:   "print available fields for an audit record file and exit",
			Sources: cli.EnvVars("NC_FIELDS"),
		},
		&cli.StringFlag{
			Name:    "sep",
			Value:   ";",
			Usage:   "set separator string for csv output",
			Sources: cli.EnvVars("NC_SEP"),
		},
		&cli.BoolFlag{
			Name:    "csv",
			Usage:   "print output data as csv with header line",
			Sources: cli.EnvVars("NC_CSV"),
		},
		&cli.BoolFlag{
			Name:    "struc",
			Value:   true,
			Usage:   "print output as structured objects",
			Sources: cli.EnvVars("NC_STRUC"),
		},
		&cli.BoolFlag{
			Name:    "tsv",
			Usage:   "print output as tab separated values",
			Sources: cli.EnvVars("NC_TSV"),
		},
		&cli.BoolFlag{
			Name:    "header",
			Usage:   "print audit record file header and exit",
			Sources: cli.EnvVars("NC_HEADER"),
		},
		&cli.BoolFlag{
			Name:    "table",
			Usage:   "print output as table view (thanks @evilsocket)",
			Sources: cli.EnvVars("NC_TABLE"),
		},
		&cli.StringFlag{
			Name:    "begin",
			Usage:   "begin character for a structure in CSV output",
			Sources: cli.EnvVars("NC_BEGIN"),
		},
		&cli.StringFlag{
			Name:    "end",
			Usage:   "end character for a structure in CSV output",
			Sources: cli.EnvVars("NC_END"),
		},
		&cli.StringFlag{
			Name:    "struct-sep",
			Value:   ",",
			Usage:   "separator character for a structure in CSV output",
			Sources: cli.EnvVars("NC_STRUCT_SEP"),
		},
		&cli.BoolFlag{
			Name:    "utc",
			Value:   true,
			Usage:   "print timestamps as UTC for CSV, table and colorized structured output",
			Sources: cli.EnvVars("NC_UTC"),
		},
		&cli.StringFlag{
			Name:    "read",
			Usage:   "read specified file, can either be a pcap or netcap audit record file",
			Sources: cli.EnvVars("NC_READ"),
		},
		&cli.BoolFlag{
			Name:    "json",
			Usage:   "print as JSON",
			Sources: cli.EnvVars("NC_JSON"),
		},
		&cli.IntFlag{
			Name:    "membuf-size",
			Value:   defaults.BufferSize,
			Usage:   "set size for membuf",
			Sources: cli.EnvVars("NC_MEMBUF_SIZE"),
		},
		&cli.BoolFlag{
			Name:    "c",
			Usage:   "force colors",
			Sources: cli.EnvVars("NC_C"),
		},
		&cli.StringFlag{
			Name:    "filter",
			Usage:   "filter audit records using an expr-lang expression (e.g., 'DstPort == 443')",
			Sources: cli.EnvVars("NC_FILTER"),
		},
	}
}
