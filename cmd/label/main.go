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

package label

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/urfave/cli/v3"

	"github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/label"
)

// Run parses the subcommand flags and handles the arguments.
// This is a compatibility wrapper for the old Run() interface.
func Run() {
	// Remove date/time from log output to prevent duplicate timestamps
	// when running in Docker/systemd (which add their own timestamps)
	log.SetFlags(0)

	// Create a new CLI app just for parsing flags
	cmd := &cli.Command{
		Name:  "label",
		Usage: "apply labels to audit records",
		Flags: GetFlags(),
		Action: func(ctx context.Context, c *cli.Command) error {
			return RunWithContext(ctx, c)
		},
	}

	if err := cmd.Run(context.Background(), os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

// RunWithContext runs the label command with a CLI context.
func RunWithContext(ctx context.Context, c *cli.Command) error {
	if c.Bool("gen-config") {
		// TODO: Update GenerateConfig to work with urfave/cli
		fmt.Println("gen-config not yet implemented with urfave/cli")
		return nil
	}

	io.PrintBuildInfo()

	flagInput := c.String("read")
	flagCustom := c.String("custom")

	if flagInput == "" && flagCustom == "" {
		log.Fatal("no input file specified. Nothing to do.")
	}

	label.Debug = c.Bool("debug")

	// configure
	label.SuricataConfigPath = c.String("suricata-config")
	label.DisableLayerMapping = c.Bool("disable-layers")
	label.UseProgressBars = c.Bool("progress")
	label.StopOnDuplicateLabels = c.Bool("strict")
	label.CollectLabels = c.Bool("collect")
	label.SetExcluded(c.String("exclude"))

	// lets go
	var err error
	if flagCustom != "" {
		err = label.CustomLabels(flagCustom, c.String("out"), c.String("sep"), "")
	} else {
		err = label.Suricata(flagInput, c.String("out"), c.Bool("description"), c.String("sep"), "")
	}
	if err != nil {
		log.Fatal(err)
	}

	return nil
}
