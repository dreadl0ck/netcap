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
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/dreadl0ck/netcap/internal/table"
	"github.com/expr-lang/expr/vm"
	"github.com/mgutz/ansi"
	"github.com/urfave/cli/v3"

	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/internal/filter"
	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/internal/utils"
	"github.com/dreadl0ck/netcap/types"
)

// Run parses the subcommand flags and handles the arguments.
// This is a compatibility wrapper for the old Run() interface.
func Run() {
	// Remove date/time from log output to prevent duplicate timestamps
	// when running in Docker/systemd (which add their own timestamps)
	log.SetFlags(0)

	// Create a new CLI app just for parsing flags
	cmd := &cli.Command{
		Name:  "dump",
		Usage: "utility to read audit record files",
		Flags: GetFlags(),
		Action: func(ctx context.Context, c *cli.Command) error {
			return RunWithContext(ctx, c)
		},
	}

	if err := cmd.Run(context.Background(), os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

// RunWithContext runs the dump command with a CLI context.
func RunWithContext(ctx context.Context, c *cli.Command) error {
	if c.Bool("gen-config") {
		return fmt.Errorf("dump --gen-config is not implemented")
	}

	flagInput := c.String("read")

	// abort if there is no input or no live capture
	if flagInput == "" {
		printHeader()
		fmt.Println(ansi.Red + "> nothing to do. need a NETCAP audit record file (.ncap.gz or .ncap) with the read flag (-read)" + ansi.Reset)
		return fmt.Errorf("dump requires --read <file.ncap[.gz]>")
	}

	if strings.HasSuffix(flagInput, ".pcap") || strings.HasSuffix(flagInput, ".pcapng") {
		printHeader()
		fmt.Println(ansi.Red + "> the dump tool is used to read netcap audit records" + ansi.Reset)
		fmt.Println(ansi.Red + "> use the capture tool create audit records from live traffic or a pcap dumpfile" + ansi.Reset)
		return fmt.Errorf("PCAP input requires net capture --read %q", flagInput)
	}

	// read dumpfile header and exit
	if c.Bool("header") { // open input file for reading
		r, errOpen := netio.Open(flagInput, c.Int("membuf-size"))
		if errOpen != nil {
			return fmt.Errorf("open audit header: %w", errOpen)
		}
		defer r.Close()

		// get header
		h, errFileHeader := r.ReadHeader()
		if errFileHeader != nil {
			return errFileHeader
		}

		// print result as table
		table.Render(os.Stdout, []string{"Field", "Value"}, [][]string{
			{"Created", utils.UnixTimeToUTC(h.Created)},
			{"Source", h.InputSource},
			{"Version", h.Version},
			{"Type", h.Type.String()},
			{"ContainsPayloads", strconv.FormatBool(h.ContainsPayloads)},
		})
		return nil
	}

	// set separators for sub structures in CSV
	types.StructureBegin = c.String("begin")
	types.StructureEnd = c.String("end")
	types.FieldSeparator = c.String("struct-sep")

	// read ncap file and print to stdout
	if filepath.Ext(flagInput) == defaults.FileExtension || filepath.Ext(flagInput) == ".gz" {
		// Compile filter expression if provided
		var filterProgram *vm.Program
		flagFilter := c.String("filter")
		if flagFilter != "" {
			// We need to read the file header first to determine the record type
			r, errOpen := netio.Open(flagInput, c.Int("membuf-size"))
			if errOpen != nil {
				return fmt.Errorf("open audit file for filter: %w", errOpen)
			}

			header, errHeader := r.ReadHeader()
			if errHeader != nil {
				_ = r.Close()
				return fmt.Errorf("read audit header for filter: %w", errHeader)
			}

			// Close the reader, we'll open it again in Dump()
			errClose := r.Close()
			if errClose != nil {
				return errClose
			}

			// Compile the filter expression
			var err error
			filterProgram, err = filter.CompileExpression(flagFilter, header.Type)
			if err != nil {
				return fmt.Errorf("compile audit filter: %w", err)
			}

			fmt.Fprintf(os.Stderr, "Using filter: %s\n", flagFilter)
		}

		err := netio.Dump(
			os.Stdout,
			netio.DumpConfig{
				Path:          flagInput,
				Separator:     c.String("sep"),
				TabSeparated:  c.Bool("tsv"),
				Structured:    c.Bool("struc"),
				Table:         c.Bool("table"),
				Selection:     c.String("select"),
				UTC:           c.Bool("utc"),
				Fields:        c.Bool("fields"),
				JSON:          c.Bool("json"),
				CSV:           c.Bool("csv"),
				ForceColors:   c.Bool("c"),
				SortTime:      c.Bool("sort-time"),
				FilterProgram: filterProgram,
			},
		)
		if err != nil {
			return err
		}

		return nil
	}

	return fmt.Errorf("unsupported audit file extension: %q (expected .ncap or .ncap.gz)", flagInput)
}
