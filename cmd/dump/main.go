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
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/evilsocket/islazy/tui"
	"github.com/expr-lang/expr/vm"
	"github.com/mgutz/ansi"

	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/filter"
	"github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
)

// Run parses the subcommand flags and handles the arguments.
func Run() {
	// Remove date/time from log output to prevent duplicate timestamps
	// when running in Docker/systemd (which add their own timestamps)
	log.SetFlags(0)
	
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

	// set separators for sub structures in CSV
	types.StructureBegin = *flagBegin
	types.StructureEnd = *flagEnd
	types.FieldSeparator = *flagStructSeparator

	// read ncap file and print to stdout
	if filepath.Ext(*flagInput) == defaults.FileExtension || filepath.Ext(*flagInput) == ".gz" {
		// Compile filter expression if provided
		var filterProgram *vm.Program
		if *flagFilter != "" {
			// We need to read the file header first to determine the record type
			r, errOpen := io.Open(*flagInput, *flagMemBufferSize)
			if errOpen != nil {
				log.Fatal("failed to open file for filter compilation:", errOpen)
			}

			header, errHeader := r.ReadHeader()
			if errHeader != nil {
				log.Fatal("failed to read header for filter compilation:", errHeader)
			}

			// Close the reader, we'll open it again in Dump()
			errClose := r.Close()
			if errClose != nil {
				log.Fatal("failed to close reader:", errClose)
			}

			// Compile the filter expression
			filterProgram, err = filter.CompileExpression(*flagFilter, header.Type)
			if err != nil {
				log.Fatal("failed to compile filter expression:", err)
			}

			fmt.Fprintf(os.Stderr, "Using filter: %s\n", *flagFilter)
		}

		err = io.Dump(
			os.Stdout,
			io.DumpConfig{
				Path:          *flagInput,
				Separator:     *flagSeparator,
				TabSeparated:  *flagTSV,
				Structured:    *flagPrintStructured,
				Table:         *flagTable,
				Selection:     *flagSelect,
				UTC:           *flagUTC,
				Fields:        *flagFields,
				JSON:          *flagJSON,
				CSV:           *flagCSV,
				ForceColors:   *flagForceColors,
				FilterProgram: filterProgram,
			},
		)
		if err != nil {
			log.Fatal(err)
		}

		return
	}
}
