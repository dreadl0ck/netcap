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
	"os"

	"github.com/namsral/flag"

	"github.com/dreadl0ck/netcap/defaults"
)

// Flags returns all flags.
func Flags() (flags []string) {
	fs.VisitAll(func(f *flag.Flag) {
		flags = append(flags, f.Name)
	})

	return
}

var (
	fs                  = flag.NewFlagSetWithEnvPrefix(os.Args[0], "NC", flag.ExitOnError)
	flagGenerateConfig  = fs.Bool("gen-config", false, "generate config")
	_                   = fs.String("config", "", "read configuration from file at path")
	flagSelect          = fs.String("select", "", "select specific fields of an audit records when generating csv or tables")
	flagFields          = fs.Bool("fields", false, "print available fields for an audit record file and exit")
	flagSeparator       = fs.String("sep", ",", "set separator string for csv output")
	flagCSV             = fs.Bool("csv", false, "print output data as csv with header line")
	flagPrintStructured = fs.Bool("struc", true, "print output as structured objects")
	flagTSV             = fs.Bool("tsv", false, "print output as tab separated values")
	flagHeader          = fs.Bool("header", false, "print audit record file header and exit")
	flagTable           = fs.Bool("table", false, "print output as table view (thanks @evilsocket)")
	flagBegin           = fs.String("begin", "(", "begin character for a structure in CSV output")
	flagEnd             = fs.String("end", ")", "end character for a structure in CSV output")
	flagStructSeparator = fs.String("struct-sep", "-", "separator character for a structure in CSV output")
	flagUTC             = fs.Bool("utc", true, "print timestamps as UTC for CSV, table and colorized structured output")
	flagInput           = fs.String("read", "", "read specified file, can either be a pcap or netcap audit record file")
	flagJSON            = fs.Bool("json", false, "print as JSON")
	flagMemBufferSize   = fs.Int("membuf-size", defaults.BufferSize, "set size for membuf")
	flagForceColors     = fs.Bool("c", false, "force colors")
)
