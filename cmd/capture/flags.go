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
	"runtime"
	"time"

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
	fs                         = flag.NewFlagSetWithEnvPrefix(os.Args[0], "NC", flag.ExitOnError)
	flagGenerateConfig         = fs.Bool("gen-config", false, "generate config")
	flagGenerateElasticIndices = fs.Bool("gen-elastic-indices", false, "generate elastic indices and mapping")
	_                          = fs.String("config", "", "read configuration from file at path")
	flagInput                  = fs.String("read", "", "read specified file, can either be a pcap or netcap audit record file")
	flagMetricsAddr            = fs.String("metrics", "", "serve metrics at")
	flagOutDir                 = fs.String("out", "", "specify output directory, will be created if it does not exist")
	flagTimeout                = fs.Duration("timeout", 1*time.Second, "set the timeout for live capture, providing a value of zero will be substituted with pcap.BlockForever.")
	flagLabels                 = fs.String("labels", "", "path to attacks for labeling audit records")

	flagScatterDuration = fs.Duration("scatter-duration", 5*time.Minute, "interval for scatter chart")
	flagScatter         = fs.Bool("scatter", true, "generate a scatter plot for labeled audit records")
	flagPPS             = fs.Bool("pps", false, "generate a line plot for throughput in packets per second")

	flagBPF = fs.String("bpf", "", "supply a BPF filter to use prior to processing packets with netcap")

	flagInclude = fs.String("include", "", "include specific decoders")
	flagExclude = fs.String("exclude", "", "exclude specific decoders")

	flagDecoders              = fs.Bool("decoders", false, "show all available decoders")
	flagPrintProtocolOverview = fs.Bool("overview", false, "print a list of all available decoders and fields")

	flagInterface    = fs.String("iface", "", "attach to network interface and capture in live mode")
	flagCompress     = fs.Bool("compress", true, "compress output with gzip")
	flagBuffer       = fs.Bool("buf", true, "buffer data in memory before writing to disk")
	flagWorkers      = fs.Int("workers", runtime.NumCPU()*2, "number of workers") // runtime.NumCPU()
	flagPacketBuffer = fs.Int("pbuf", defaults.PacketBuffer, "set packet buffer size, for channels that feed data to workers")

	flagAnalyzer = fs.String("analyzer", "", "the analyzer to use")

	flagCPUProfile    = fs.Bool("cpuprof", false, "create cpu profile")
	flagMemProfile    = fs.Bool("memprof", false, "create memory profile")
	flagIgnoreUnknown = fs.Bool("ignore-unknown", true, "disable writing unknown packets into a pcap file")
	flagPromiscMode   = fs.Bool("promisc", true, "toggle promiscuous mode for live capture")
	flagSnapLen       = fs.Int("snaplen", defaults.SnapLen, "configure snaplen for live capture from interface")

	flagTime = fs.Bool("time", false, "print processing time even in quiet mode")

	flagBaseLayer     = fs.String("base", "ethernet", "select base layer")
	flagDecodeOptions = fs.String("opts", "lazy", "select decoding options")
	flagPayload       = fs.Bool("payload", false, "capture payload for supported layers")

	flagCSV              = fs.Bool("csv", false, "output data as CSV")
	flagUNIX             = fs.Bool("unix", false, "output data via unix sockets")
	flagNull             = fs.Bool("null", false, "write no data to disk")
	flagElastic          = fs.Bool("elastic", false, "write data to elastic db")
	flagElasticAddrs     = fs.String("elastic-addrs", "", "elastic db endpoints to write data to")
	flagElasticUser      = fs.String("elastic-user", "", "elastic db username")
	flagElasticPass      = fs.String("elastic-pass", "", "elastic db password")
	flagBulkSizeGoPacket = fs.Int("elastic-bulk-gopacket", 2000, "elastic bulk size for gopacket audit records")
	flagBulkSizeCustom   = fs.Int("elastic-bulk-custom", 1000, "elastic bulk size for custom audit records")
	flagKibanaEndpoint   = fs.String("kibana", "", "kibana endpoint URL")
	flagProto            = fs.Bool("proto", true, "output data as protobuf")
	flagJSON             = fs.Bool("json", false, "output data as JSON")
	flagContext          = fs.Bool("context", true, "add packet flow context to selected audit records")
	flagHTTPShutdown     = fs.Bool("http-shutdown", false, "create local endpoint to trigger teardown via HTTP")

	flagMemBufferSize  = fs.Int("membuf-size", defaults.BufferSize, "set size for membuf")
	flagListInterfaces = fs.Bool("interfaces", false, "list all visible network interfaces")
	flagQuiet          = fs.Bool("quiet", false, "don't print infos to stdout")
	flagPrintProgress  = fs.Bool("progress", false, "force printing progress to stderr even in quiet mode")

	flagFileStorage = fs.String("fileStorage", "", "path to extracted files")

	flagReverseDNS    = fs.Bool("reverse-dns", false, "resolve ips to domains via the operating systems default dns resolver")
	flagLocalDNS      = fs.Bool("local-dns", false, "resolve DNS locally via hosts file in the database dir")
	flagMACDB         = fs.Bool("macDB", true, "use mac to vendor database for device profiling")
	flagJa3DB         = fs.Bool("ja3DB", true, "use ja3 database for device profiling")
	flagServiceDB     = fs.Bool("serviceDB", true, "use serviceDB for device profiling")
	flagGeolocationDB = fs.Bool("geoDB", false, "use geolocation for device profiling")
	flagDPI           = fs.Bool("dpi", false, "use DPI libs to enrich IPProfile audit records")

	flagFreeOSMemory          = fs.Int("free-os-mem", 0, "free OS memory every X minutes, disabled if set to 0")
	flagReassembleConnections = fs.Bool("reassemble-connections", true, "reassemble TCP connections")

	flagTCPDebug  = fs.Bool("tcp-debug", false, "add debug output for TCP connections to debug.log")
	flagSaveConns = fs.Bool("conns", false, "save raw TCP connections")

	flagCalcEntropy = fs.Bool("entropy", false, "enable entropy calculation for Eth,IP,TCP and UDP payloads")
	flagLogErrors   = fs.Bool("log-errors", false, "enable verbose packet decoding error logging")

	// reassembly.
	flagFlushevery           = fs.Int("flushevery", defaults.FlushEvery, "flush assembler every N packets")
	flagDefragIPv4           = fs.Bool("ip4defrag", defaults.DefragIPv4, "Defragment IPv4 packets")
	flagChecksum             = fs.Bool("checksum", defaults.Checksum, "check TCP checksum")
	flagNooptcheck           = fs.Bool("nooptcheck", defaults.NoOptCheck, "do not check TCP options (useful to ignore MSS on captures with TSO)")
	flagIgnorefsmerr         = fs.Bool("ignorefsmerr", defaults.IgnoreFSMErr, "ignore TCP FSM errors")
	flagAllowmissinginit     = fs.Bool("allowmissinginit", defaults.AllowMissingInit, "support streams without SYN/SYN+ACK/ACK sequence")
	flagHexdump              = fs.Bool("hexdump", false, "dump packets used in stream reassembly as hex to the reassembly.log file")
	flagWaitForConnections   = fs.Bool("wait-conns", true, "wait for all connections to finish processing before cleanup")
	flagWriteincomplete      = fs.Bool("writeincomplete", false, "write incomplete response")
	flagStreamDecoderBufSize = fs.Int("sbuf-size", 1000, "size for channel used to pass data to the stream decoders. default is unbuffered")
	flagReassemblyDebug      = fs.Bool("reassembly-debug", false, "if true, the reassembly will log verbose debugging information")

	flagNoPrompt   = fs.Bool("noprompt", false, "don't prompt for interaction during execution")
	flagDebug      = fs.Bool("debug", false, "display debug information")
	flagMemprofile = fs.String("memprofile", "", "write memory profile")

	flagConnFlushInterval              = fs.Int("conn-flush-interval", defaults.ConnFlushInterval, "flush connections every X flows")
	flagConnTimeOut                    = fs.Duration("conn-timeout", defaults.ConnTimeOut, "close connections older than X seconds")
	flagFlowFlushInterval              = fs.Int("flow-flush-interval", defaults.FlowFlushInterval, "flushes flows every X flows")
	flagFlowTimeOut                    = fs.Duration("flow-timeout", defaults.FlowTimeOut, "closes flows older than flowTimeout")
	flagClosePendingTimeout            = fs.Duration("close-pending-timeout", defaults.ClosePendingTimeout, "reassembly: close connections that have pending bytes")
	flagCloseInactiveTimeout           = fs.Duration("close-inactive-timeout", defaults.CloseInactiveTimeout, "reassembly: close connections that are inactive")
	flagUseRE2                         = fs.Bool("re2", true, "if true uses the default golang re2 regex engine for service detection")
	flagStopAfterHarvesterMatch        = fs.Bool("stop-after-harvester-match", true, "stop processing the conversation after the first credential harvester returned a result")
	flagStopAfterServiceProbeMatch     = fs.Bool("stop-after-service-match", true, "stop processing the conversation after the first service probe returned a result")
	flagStopAfterServiceCategoryMiss   = fs.Bool("stop-after-service-category-miss", true, "stop processing the conversation after the first service probe returned a result")
	flagIgnoreInitErrs                 = fs.Bool("ignore-init-errors", true, "ignore errors from initializing custom decoders")
	flagDisableGenericVersionHarvester = fs.Bool("disable-generic-software-harvester", true, "disable the generic software harvester regex")
	flagRemoveClosedStreams            = fs.Bool("remove-closed-streams", false, "remove tcp streams that receive a FIN or RST packet from the stream pool")
	flagEncode                         = fs.Bool("encode", false, "encode data written into CSV file")

	flagBannerSize          = fs.Int("bsize", 256, "size of the stored service banners in bytes")
	flagHarvesterBannerSize = fs.Int("hbsize", 256, "size of the data passed to the credential harvesters in bytes")
	flagCustomCredsRegex    = fs.String("reCustom", "", "possibility of passing a custom regex for harvesting credentials")
	flagStreamBufferSize    = fs.Int("stream-buffer", 10000, "input channel size for TCP / UDP stream processors")
	flagNumStreamWorkers    = fs.Int("stream-workers", 10000, "number of TCP / UDP stream workers")

	flagCompressionBlockSize = fs.Int("compression-block-size", defaults.CompressionBlockSize, "block size used for parallel compression")
	flagCompressionLevel     = fs.String("compression-level", compressionLevelToString(defaults.CompressionLevel), "level of compression")
)
