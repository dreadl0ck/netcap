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
	flagInput  = flag.String("r", "", "read specified file, can either be a pcap or netcap audit record file")
	flagOutDir = flag.String("out", "", "specify output directory, will be created if it does not exist")

	flagBPF = flag.String("bpf", "", "supply a BPF filter to use prior to processing packets with netcap")

	flagInclude = flag.String("include", "", "include specific encoders")
	flagExclude = flag.String("exclude", "LinkFlow,NetworkFlow,TransportFlow", "exclude specific encoders")

	flagEncoders              = flag.Bool("encoders", false, "show all available encoders")
	flagPrintProtocolOverview = flag.Bool("overview", false, "print a list of all available encoders and fields")

	flagInterface    = flag.String("iface", "", "attach to network interface and capture in live mode")
	flagCompress     = flag.Bool("comp", true, "compress output with gzip")
	flagBuffer       = flag.Bool("buf", true, "buffer data in memory before writing to disk")
	flagWorkers      = flag.Int("workers", 1000, "number of workers")
	flagPacketBuffer = flag.Int("pbuf", 100, "set packet buffer size, for channels that feed data to workers")

	flagCPUProfile    = flag.Bool("cpuprof", false, "create cpu profile")
	flagMemProfile    = flag.Bool("memprof", false, "create memory profile")
	flagIngoreUnknown = flag.Bool("ignore-unknown", false, "disable writing unknown packets into a pcap file")
	flagPromiscMode   = flag.Bool("promisc", true, "toggle promiscous mode for live capture")
	flagSnapLen       = flag.Int("snaplen", 1514, "configure snaplen for live capture from interface")

	flagVersion = flag.Bool("version", false, "print netcap package version and exit")

	flagBaseLayer     = flag.String("base", "ethernet", "select base layer")
	flagDecodeOptions = flag.String("opts", "datagrams", "select decoding options")
	flagPayload       = flag.Bool("payload", false, "capture payload for supported layers")

	flagCSV     = flag.Bool("csv", false, "output data as CSV instead of audit records")
	flagContext = flag.Bool("context", true, "add packet flow context to selected audit records")

	flagMemBufferSize  = flag.Int("membuf-size", 1024*1024*10, "set size for membuf")
	flagListInterfaces = flag.Bool("interfaces", false, "list all visible network interfaces")
	flagQuiet          = flag.Bool("quiet", false, "don't print infos to stdout")
)
