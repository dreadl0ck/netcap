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

import "flag"

var (
	// dump
	flagSelect          = flag.String("select", "", "select specific fields of an audit records when generating csv or tables")
	flagFields          = flag.Bool("fields", false, "print available fields for an audit record file and exit")
	flagSeparator       = flag.String("sep", ",", "set separator string for csv output")
	flagCSV             = flag.Bool("csv", false, "print output data as csv with header line")
	flagPrintStructured = flag.Bool("struc", false, "print output as structured objects")
	flagTSV             = flag.Bool("tsv", false, "print output as tab separated values")
	flagHeader          = flag.Bool("header", false, "print audit record file header and exit")
	flagTable           = flag.Bool("table", false, "print output as table view (thanks @evilsocket)")
	flagBegin           = flag.String("begin", "(", "begin character for a structure in CSV output")
	flagEnd             = flag.String("end", ")", "end character for a structure in CSV output")
	flagStructSeparator = flag.String("struct-sep", "-", "separator character for a structure in CSV output")
	flagUTC             = flag.Bool("utc", false, "print timestamps as UTC when using select csv")
	flagInput           = flag.String("r", "", "read specified file, can either be a pcap or netcap audit record file")
	flagVersion         = flag.Bool("version", false, "print netcap package version and exit")
	flagJSON            = flag.Bool("json", false, "print as JSON")
	flagMemBufferSize   = flag.Int("membuf-size", 1024*1024*10, "set size for membuf")
)
