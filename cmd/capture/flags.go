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
)

var (
	flagBPF          = flag.String("bpf", "", "supply a BPF filter to use prior to processing packets with netcap")
	flagInclude      = flag.String("include", "", "include specific encoders")
	flagExclude      = flag.String("exclude", "", "exclude specific encoders")
	flagEncoders     = flag.Bool("encoders", false, "show all available encoders")
	flagInput        = flag.String("r", "", "read specified file, can either be a pcap or netcap audit record file")
	flagInterface    = flag.String("iface", "", "attach to network interface and capture in live mode")
	flagSelect       = flag.String("select", "", "select specific fields of an audit records when generating csv or tables")
	flagFields       = flag.Bool("fields", false, "print available fields for an audit record file and exit")
	flagCompress     = flag.Bool("comp", true, "compress output with gzip")
	flagBuffer       = flag.Bool("buf", true, "buffer data in memory before writing to disk")
	flagWorkers      = flag.Int("workers", 1000, "number of workers")
	flagSeparator    = flag.String("sep", ",", "set separator string for csv output")
	flagPacketBuffer = flag.Int("pbuf", 100, "set packet buffer size, for channels that feed data to workers")
	flagOutDir       = flag.String("out", "", "specify output directory, will be created if it does not exist")

	flagCPUProfile = flag.Bool("cpuprof", false, "create cpu profile")
	flagMemProfile = flag.Bool("memprof", false, "create memory profile")

	flagUTC   = flag.Bool("utc", false, "print timestamps as UTC when using select csv")
	flagToUTC = flag.String("ts2utc", "", "util to convert sencods.microseconds timestamp to UTC")

	flagCSV             = flag.Bool("csv", false, "print output data as csv with header line")
	flagPrintStructured = flag.Bool("struc", false, "print output as structured objects")
	flagTSV             = flag.Bool("tsv", false, "print output as tab separated values")

	flagIngoreUnknown = flag.Bool("ignore-unknown", false, "disable writing unknown packets into a pcap file")

	flagHeader      = flag.Bool("header", false, "print audit record file header and exit")
	flagVersion     = flag.Bool("version", false, "print netcap package version and exit")
	flagTable       = flag.Bool("table", false, "print output as table view (thanks @evilsocket)")
	flagCheckFields = flag.Bool("check", false, "check number of occurences of the separator, in fields of an audit record file")

	flagPromiscMode           = flag.Bool("promisc", true, "toggle promiscous mode for live capture")
	flagSnapLen               = flag.Int("snaplen", 1024, "configure snaplen for live capture from interface")
	flagPrintProtocolOverview = flag.Bool("overview", false, "print a list of all available encoders and fields")

	flagBaseLayer     = flag.String("base", "ethernet", "select base layer")
	flagDecodeOptions = flag.String("opts", "lazy", "select decoding options")
	flagPayload       = flag.Bool("payload", false, "capture payload for supported layers")

	flagBegin           = flag.String("begin", "(", "begin character for a structure in CSV output")
	flagEnd             = flag.String("end", ")", "end character for a structure in CSV output")
	flagStructSeparator = flag.String("struct-sep", "-", "separator character for a structure in CSV output")

	// move to exporter?
	flagExport         = flag.Bool("export", true, "export prometheus metrics")
	flagMetricsAddress = flag.String("address", "127.0.0.1:4444", "metrics address")
)
