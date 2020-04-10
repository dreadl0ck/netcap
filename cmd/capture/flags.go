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

package capture

import (
	"github.com/namsral/flag"
	"os"
)

var (
	fs         = flag.NewFlagSetWithEnvPrefix(os.Args[0], "NC", flag.ExitOnError)
	flagInput  = fs.String("r", "", "read specified file, can either be a pcap or netcap audit record file")
	flagOutDir = fs.String("out", "", "specify output directory, will be created if it does not exist")

	flagBPF = fs.String("bpf", "", "supply a BPF filter to use prior to processing packets with netcap")

	flagInclude = fs.String("include", "", "include specific encoders")
	flagExclude = fs.String("exclude", "LinkFlow,NetworkFlow,TransportFlow", "exclude specific encoders")

	flagEncoders              = fs.Bool("encoders", false, "show all available encoders")
	flagPrintProtocolOverview = fs.Bool("overview", false, "print a list of all available encoders and fields")

	flagInterface    = fs.String("iface", "", "attach to network interface and capture in live mode")
	flagCompress     = fs.Bool("comp", true, "compress output with gzip")
	flagBuffer       = fs.Bool("buf", true, "buffer data in memory before writing to disk")
	flagWorkers      = fs.Int("workers", 12, "number of workers")
	flagPacketBuffer = fs.Int("pbuf", 100, "set packet buffer size, for channels that feed data to workers")

	flagCPUProfile    = fs.Bool("cpuprof", false, "create cpu profile")
	flagMemProfile    = fs.Bool("memprof", false, "create memory profile")
	flagIgnoreUnknown = fs.Bool("ignore-unknown", true, "disable writing unknown packets into a pcap file")
	flagPromiscMode   = fs.Bool("promisc", true, "toggle promiscous mode for live capture")
	flagSnapLen       = fs.Int("snaplen", 1514, "configure snaplen for live capture from interface")

	flagVersion = fs.Bool("version", false, "print netcap package version and exit")

	flagBaseLayer     = fs.String("base", "ethernet", "select base layer")
	flagDecodeOptions = fs.String("opts", "datagrams", "select decoding options")
	flagPayload       = fs.Bool("payload", false, "capture payload for supported layers")

	flagCSV     = fs.Bool("csv", false, "output data as CSV instead of audit records")
	flagContext = fs.Bool("context", true, "add packet flow context to selected audit records")

	flagMemBufferSize  = fs.Int("membuf-size", 1024*1024*10, "set size for membuf")
	flagListInterfaces = fs.Bool("interfaces", false, "list all visible network interfaces")
	flagQuiet          = fs.Bool("quiet", false, "don't print infos to stdout")

	flagFileStorage = fs.String("fileStorage", "", "path to created extracted files (currently only for HTTP)")

	flagReverseDNS    = fs.Bool("reverse-dns", false, "resolve ips to domains via the operating systems default dns resolver")
	flagLocalDNS      = fs.Bool("local-dns", false, "resolve DNS locally via hosts file in the database dir")
	flagMACDB         = fs.Bool("macDB", false, "use mac to vendor database for device profiling")
	flagJa3DB         = fs.Bool("ja3DB", false, "use ja3 database for device profiling")
	flagServiceDB     = fs.Bool("serviceDB", false, "use serviceDB for device profiling")
	flagGeolocationDB = fs.Bool("geoDB", false, "use geolocation for device profiling")
	flagDPI           = fs.Bool("dpi", false, "use DPI for device profiling")
)
