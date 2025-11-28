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

package inject

import (
	"github.com/urfave/cli/v3"
)

// Flag names.
const (
	flagNameRules          = "rules"
	flagNameQueue          = "queue"
	flagNameInterface      = "iface"
	flagNameAutoIPTables   = "iptables"
	flagNameIPTablesTarget = "target"
	flagNameVerbose        = "verbose"
	flagNameDryRun         = "dry-run"
	flagNameLogActions     = "log-actions"
	flagNameLogFile        = "log-file"
	flagNameMaxQueueLen    = "max-queue-len"
	flagNameListRules      = "list-rules"
	flagNameValidate       = "validate"
	flagNameNoWarning      = "no-warning"
)

// Flag values.
var (
	flagRules          string
	flagQueue          int
	flagInterface      string
	flagAutoIPTables   bool
	flagIPTablesTarget string
	flagVerbose        bool
	flagDryRun         bool
	flagLogActions     bool
	flagLogFile        string
	flagMaxQueueLen    int
	flagListRules      bool
	flagValidate       bool
	flagNoWarning      bool
)

// GetFlags returns the CLI flags for the inject subcommand.
func GetFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:        flagNameRules,
			Aliases:     []string{"r"},
			Usage:       "path to injection rules YAML file or directory",
			Destination: &flagRules,
			Required:    true,
		},
		&cli.IntFlag{
			Name:        flagNameQueue,
			Aliases:     []string{"q"},
			Usage:       "nfqueue number to use (Linux only)",
			Value:       0,
			Destination: &flagQueue,
		},
		&cli.StringFlag{
			Name:        flagNameInterface,
			Aliases:     []string{"i"},
			Usage:       "network interface for packet injection",
			Destination: &flagInterface,
		},
		&cli.BoolFlag{
			Name:        flagNameAutoIPTables,
			Usage:       "automatically configure iptables rules for nfqueue (Linux only)",
			Destination: &flagAutoIPTables,
		},
		&cli.StringFlag{
			Name:        flagNameIPTablesTarget,
			Aliases:     []string{"t"},
			Usage:       "iptables target specification (e.g., '-d 192.168.1.0/24')",
			Destination: &flagIPTablesTarget,
		},
		&cli.BoolFlag{
			Name:        flagNameVerbose,
			Aliases:     []string{"v"},
			Usage:       "enable verbose output",
			Destination: &flagVerbose,
		},
		&cli.BoolFlag{
			Name:        flagNameDryRun,
			Usage:       "evaluate rules without actually injecting or modifying packets",
			Destination: &flagDryRun,
		},
		&cli.BoolFlag{
			Name:        flagNameLogActions,
			Usage:       "log all injection actions to file",
			Value:       true,
			Destination: &flagLogActions,
		},
		&cli.StringFlag{
			Name:        flagNameLogFile,
			Usage:       "path to action log file",
			Value:       "injection.log",
			Destination: &flagLogFile,
		},
		&cli.IntFlag{
			Name:        flagNameMaxQueueLen,
			Usage:       "maximum number of packets to queue",
			Value:       1024,
			Destination: &flagMaxQueueLen,
		},
		&cli.BoolFlag{
			Name:        flagNameListRules,
			Aliases:     []string{"l"},
			Usage:       "list loaded rules and exit",
			Destination: &flagListRules,
		},
		&cli.BoolFlag{
			Name:        flagNameValidate,
			Usage:       "validate rules and exit",
			Destination: &flagValidate,
		},
		&cli.BoolFlag{
			Name:        flagNameNoWarning,
			Usage:       "suppress the warning banner",
			Destination: &flagNoWarning,
		},
	}
}

// Flags returns the flag names for shell completion.
func Flags() []string {
	return []string{
		flagNameRules,
		flagNameQueue,
		flagNameInterface,
		flagNameAutoIPTables,
		flagNameIPTablesTarget,
		flagNameVerbose,
		flagNameDryRun,
		flagNameLogActions,
		flagNameLogFile,
		flagNameMaxQueueLen,
		flagNameListRules,
		flagNameValidate,
		flagNameNoWarning,
	}
}
