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

package capture

import (
	"os"

	"github.com/dreadl0ck/netcap"
	"github.com/namsral/flag"
)

func Flags() (flags []string) {
	fs.VisitAll(func(f *flag.Flag) {
		flags = append(flags, f.Name)
	})
	return
}

var (
	fs                 = flag.NewFlagSetWithEnvPrefix(os.Args[0], "NC", flag.ExitOnError)
	flagGenerateConfig = fs.Bool("gen-config", false, "generate config")
	flagConfig         = fs.String("config", "", "read configuration from file at path")
	flagInput          = fs.String("read", "", "read specified file, can either be a pcap or netcap audit record file")
	flagOutDir         = fs.String("out", "", "specify output directory, will be created if it does not exist")

	flagBPF = fs.String("bpf", "", "supply a BPF filter to use prior to processing packets with netcap")

	flagInclude = fs.String("include", "", "include specific encoders")
	flagExclude = fs.String("exclude", "", "exclude specific encoders")

	flagEncoders              = fs.Bool("encoders", false, "show all available encoders")
	flagPrintProtocolOverview = fs.Bool("overview", false, "print a list of all available encoders and fields")

	flagInterface    = fs.String("iface", "", "attach to network interface and capture in live mode")
	flagCompress     = fs.Bool("comp", true, "compress output with gzip")
	flagBuffer       = fs.Bool("buf", true, "buffer data in memory before writing to disk")
	flagWorkers      = fs.Int("workers", 1, "number of workers")
	flagPacketBuffer = fs.Int("pbuf", netcap.DefaultPacketBuffer, "set packet buffer size, for channels that feed data to workers")

	flagCPUProfile    = fs.Bool("cpuprof", false, "create cpu profile")
	flagMemProfile    = fs.Bool("memprof", false, "create memory profile")
	flagIgnoreUnknown = fs.Bool("ignore-unknown", true, "disable writing unknown packets into a pcap file")
	flagPromiscMode   = fs.Bool("promisc", true, "toggle promiscous mode for live capture")
	flagSnapLen       = fs.Int("snaplen", netcap.DefaultSnapLen, "configure snaplen for live capture from interface")

	flagTime    = fs.Bool("time", false, "print processing time even in quiet mode")
	flagVersion = fs.Bool("version", false, "print netcap package version and exit")

	flagBaseLayer     = fs.String("base", "ethernet", "select base layer")
	flagDecodeOptions = fs.String("opts", "datagrams", "select decoding options")
	flagPayload       = fs.Bool("payload", false, "capture payload for supported layers")

	flagCSV     = fs.Bool("csv", false, "output data as CSV instead of audit records")
	flagContext = fs.Bool("context", true, "add packet flow context to selected audit records")

	flagMemBufferSize  = fs.Int("membuf-size", netcap.DefaultBufferSize, "set size for membuf")
	flagListInterfaces = fs.Bool("interfaces", false, "list all visible network interfaces")
	flagQuiet          = fs.Bool("quiet", false, "don't print infos to stdout")

	flagFileStorage = fs.String("fileStorage", "", "path to created extracted files (currently only for HTTP)")

	flagReverseDNS    = fs.Bool("reverse-dns", false, "resolve ips to domains via the operating systems default dns resolver")
	flagLocalDNS      = fs.Bool("local-dns", false, "resolve DNS locally via hosts file in the database dir")
	flagMACDB         = fs.Bool("macDB", true, "use mac to vendor database for device profiling")
	flagJa3DB         = fs.Bool("ja3DB", true, "use ja3 database for device profiling")
	flagServiceDB     = fs.Bool("serviceDB", true, "use serviceDB for device profiling")
	flagGeolocationDB = fs.Bool("geoDB", false, "use geolocation for device profiling")
	flagDPI           = fs.Bool("dpi", false, "use DPI for device profiling")

	flagFreeOSMemory          = fs.Int("free-os-mem", 0, "free OS memory every X minutes, disabled if set to 0")
	flagReassembleConnections = fs.Bool("reassemble-connections", true, "reassemble TCP connections")

	flagTCPDebug    = fs.Bool("tcp-debug", false, "add debug output for TCP connections to debug.log")
	flagSaveConns   = fs.Bool("conns", false, "save raw TCP connections")

	flagCalcEntropy             = fs.Bool("entropy", false, "enable entropy calculation for Eth,IP,TCP and UDP payloads")
	flagLogErrors               = fs.Bool("log-errors", false, "enable verbose packet decoding error logging")
	flagFlushevery              = fs.Int("flushevery", netcap.DefaultFlushEvery, "flush assembler every N packets")
	flagNodefrag                = fs.Bool("nodefrag", true, "if true, do not do IPv4 defrag")
	flagChecksum                = fs.Bool("checksum", false, "check TCP checksum")
	flagNooptcheck              = fs.Bool("nooptcheck", true, "do not check TCP options (useful to ignore MSS on captures with TSO)")
	flagIgnorefsmerr            = fs.Bool("ignorefsmerr", false, "ignore TCP FSM errors")
	flagAllowmissinginit        = fs.Bool("allowmissinginit", netcap.DefaultAllowMissingInit, "support streams without SYN/SYN+ACK/ACK sequence")
	flagDebug                   = fs.Bool("debug", false, "display debug information")
	flagHexdump                 = fs.Bool("hexdump", false, "dump packets used in stream reassembly as hex to the reassembly.log file")
	flagWaitForConnections      = fs.Bool("wait-conns", true, "wait for all connections to finish processing before cleanup")
	flagWriteincomplete         = fs.Bool("writeincomplete", false, "write incomplete response")
	flagMemprofile              = fs.String("memprofile", "", "write memory profile")
	flagConnFlushInterval       = fs.Int("conn-flush-interval", netcap.DefaultConnFlushInterval, "flush connections every X flows")
	flagConnTimeOut             = fs.Duration("conn-timeout", netcap.DefaultConnTimeOut, "close connections older than X seconds")
	flagFlowFlushInterval       = fs.Int("flow-flush-interval", netcap.DefaultFlowFlushInterval, "flushes flows every X flows")
	flagFlowTimeOut             = fs.Duration("flow-timeout", netcap.DefaultFlowTimeOut, "closes flows older than flowTimeout")
	flagClosePendingTimeout     = fs.Duration("close-pending-timeout", netcap.DefaultClosePendingTimeout, "reassembly: close connections that have pending bytes")
	flagCloseInactiveTimeout    = fs.Duration("close-inactive-timeout", netcap.DefaultCloseInactiveTimeout, "reassembly: close connections that are inactive")
	flagUseRE2                  = fs.Bool("re2", true, "if true uses the default golang re2 regex engine for service detection")
	flagStopAfterHarvesterMatch = fs.Bool("stop-after-harvester-match", true, "stop processing the conversation after the first harvester returned a result")
	flagBannerSize              = fs.Int("bsize", 512, "size of the stored service banners in bytes")
	flagHarvesterBannerSize     = fs.Int("hbsize", 512, "size of the data passed to the credential harvesters in bytes")
	flagStreamDecoderBufSize    = fs.Int("sbuf-size", 0, "size for channel used to pass data to the stream decoders. default is unbuffered")
	flagReassemblyDebug         = fs.Bool("reassembly-debug", false, "if true, the reassembly will log verbose debugging information")
	flagCustomCredsRegex        = fs.String("reCustom", "", "possibility of passing a custom regex for harvesting credentials")
)
