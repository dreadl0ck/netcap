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

package dump

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/evilsocket/islazy/tui"
	"github.com/mgutz/ansi"

	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"

	"github.com/dreadl0ck/netcap/internal/sqlite"
)

var errAborted = errors.New("operation aborted by user")

// Run parses the subcommand flags and handles the arguments.
func Run() {
	// parse commandline flags
	fs.Usage = printUsage

	err := fs.Parse(os.Args[2:])
	if err != nil {
		log.Fatal(err)
	}

	if *flagGenerateConfig {
		io.GenerateConfig(fs, "dump")

		return
	}

	// abort if there is no input or no live capture
	if *flagInput == "" {
		printHeader()
		fmt.Println(ansi.Red + "> nothing to do. need a NETCAP audit record file (.ncap.gz or .ncap) with the read flag (-read)" + ansi.Reset)
		os.Exit(1)
	}

	if strings.HasSuffix(*flagInput, ".pcap") || strings.HasSuffix(*flagInput, ".pcapng") {
		printHeader()
		fmt.Println(ansi.Red + "> the dump tool is used to read netcap audit records" + ansi.Reset)
		fmt.Println(ansi.Red + "> use the capture tool create audit records from live traffic or a pcap dumpfile" + ansi.Reset)
		os.Exit(1)
	}

	// read dumpfile header and exit
	if *flagHeader { // open input file for reading
		r, errOpen := io.Open(*flagInput, *flagMemBufferSize)
		if errOpen != nil {
			panic(errOpen)
		}

		// get header
		h, errFileHeader := r.ReadHeader()
		if errFileHeader != nil {
			log.Fatal(errFileHeader)
		}

		// print result as table
		tui.Table(os.Stdout, []string{"Field", "Value"}, [][]string{
			{"Created", utils.UnixTimeToUTC(h.Created)},
			{"Source", h.InputSource},
			{"Version", h.Version},
			{"Type", h.Type.String()},
			{"ContainsPayloads", strconv.FormatBool(h.ContainsPayloads)},
		})
		os.Exit(0) // bye bye
	}

	switch {
	case isAuditRecordDirectory(*flagInput):
		if *flagSelect != "" {
			fmt.Println(ansi.Red + "field selection is (currently) not supported when dumping to SQLite" + ansi.Reset)
			os.Exit(1)
		}

		// ensure we start with a fresh database at all times, so that results
		// from different directories don't get merged into a single database.
		if _, err := os.Stat(*flagSQLite); err == nil {
			shouldPrompt := true // TODO: make this depend on flags, similar to collector init
			if shouldPrompt {
				msg := "database output path already exists! Overwrite?"
				if !utils.Confirm(msg) {
					fmt.Println(ansi.Red + fmt.Sprintf("> %v", errAborted) + ansi.Reset)
					os.Exit(1)
				}

				if err := os.Remove(*flagSQLite); err != nil {
					fmt.Println(ansi.Red + fmt.Sprintf("> failed removing existing database %q: %v", *flagSQLite, err) + ansi.Reset)
					os.Exit(1)
				}
			}
		}

		// read all ncap files, and insert into SQLite database
		err = sqlite.Dump(
			context.Background(),
			os.Stdout,
			sqlite.DumpConfig{
				Paths:         []string{*flagInput}, // TODO: support multiple (non-directory) paths?
				Output:        *flagSQLite,
				MemBufferSize: *flagMemBufferSize,
				Selection:     *flagSelect,
				Debug:         *flagDebug,
			})
	case isAuditRecordFile(*flagInput):
		// set separators for sub structures in CSV
		types.StructureBegin = *flagBegin
		types.StructureEnd = *flagEnd
		types.FieldSeparator = *flagStructSeparator

		// read ncap file and print to stdout
		err = io.Dump(
			os.Stdout,
			io.DumpConfig{
				Path:         *flagInput,
				Separator:    *flagSeparator,
				TabSeparated: *flagTSV,
				Structured:   *flagPrintStructured,
				Table:        *flagTable,
				Selection:    *flagSelect,
				UTC:          *flagUTC,
				Fields:       *flagFields,
				JSON:         *flagJSON,
				CSV:          *flagCSV,
				ForceColors:  *flagForceColors,
			},
		)
	default:
		fi, err := os.Open(*flagInput)
		if err != nil {
			fmt.Println(ansi.Red + fmt.Sprintf("> failed opening %q: %v", *flagInput, errors.Unwrap(err)) + ansi.Reset)
			os.Exit(1)
		}

		fmt.Println(ansi.Red + fmt.Sprintf("> input %q doesn't contain audit record file(s)", fi.Name()) + ansi.Reset)
		os.Exit(1)
	}

	if err != nil {
		log.Fatal(err)
	}
}

func isAuditRecordDirectory(input string) bool {
	fi, err := os.Stat(input)
	if err == nil && fi.IsDir() {
		return true
	}

	return false
}

func isAuditRecordFile(input string) bool {
	return filepath.Ext(input) == defaults.FileExtension || filepath.Ext(input) == ".gz"
}
