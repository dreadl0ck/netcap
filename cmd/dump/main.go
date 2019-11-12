/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
	"github.com/evilsocket/islazy/tui"
)

func main() {

	// parse commandline flags
	flag.Usage = printUsage
	flag.Parse()

	// print version and exit
	if *flagVersion {
		fmt.Println(netcap.Version)
		os.Exit(0)
	}

	// read dumpfile header and exit
	if *flagHeader {

		// open input file for reading
		r, err := netcap.Open(*flagInput)
		if err != nil {
			panic(err)
		}

		// get header
		// this will panic if the header is corrupted
		h := r.ReadHeader()

		// print result as table
		tui.Table(os.Stdout, []string{"Field", "Value"}, [][]string{
			{"Created", utils.TimeToUTC(h.Created)},
			{"Source", h.InputSource},
			{"Version", h.Version},
			{"Type", h.Type.String()},
			{"ContainsPayloads", strconv.FormatBool(h.ContainsPayloads)},
		})
		os.Exit(0) // bye bye
	}

	// set separators for sub structures in CSV
	types.Begin = *flagBegin
	types.End = *flagEnd
	types.Separator = *flagStructSeparator

	// read ncap file and print to stdout
	if filepath.Ext(*flagInput) == ".ncap" || filepath.Ext(*flagInput) == ".gz" {
		netcap.Dump(*flagInput, *flagSeparator, *flagTSV, *flagPrintStructured, *flagTable, *flagSelect, *flagUTC, *flagFields, *flagJSON)
		return
	}
}
