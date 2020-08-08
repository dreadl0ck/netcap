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

package export

import (
	"os"
	"runtime"

	"github.com/namsral/flag"

	"github.com/dreadl0ck/netcap"
)

// Flags returns all flags.
func Flags() (flags []string) {
	fs.VisitAll(func(f *flag.Flag) {
		flags = append(flags, f.Name)
	})

	return
}

var (
	fs                 = flag.NewFlagSetWithEnvPrefix(os.Args[0], "NC", flag.ExitOnError)
	flagGenerateConfig = fs.Bool("gen-config", false, "generate config")
	_                  = fs.String("config", "", "read configuration from file at path")
	flagMetricsAddress = fs.String("address", "127.0.0.1:7777", "set address for exposing metrics")
	flagDumpJSON       = fs.Bool("dumpJson", false, "dump as JSON")
	flagReplay         = fs.Bool("replay", false, "replay traffic (only works when exporting audit records directly!)")
	flagDir            = fs.String("dir", "", "path to directory with netcap audit records")
	flagInput          = fs.String("read", "", "read specified file, can either be a pcap or netcap audit record file")
	flagInterface      = fs.String("iface", "", "attach to network interface and capture in live mode")
	flagWorkers        = fs.Int("workers", runtime.NumCPU(), "number of workers")
	flagPacketBuffer   = fs.Int("pbuf", netcap.DefaultPacketBuffer, "set packet buffer size, for channels that feed data to workers")
	flagIngoreUnknown  = fs.Bool("ignore-unknown", false, "disable writing unknown packets into a pcap file")
	flagPromiscMode    = fs.Bool("promisc", true, "toggle promiscuous mode for live capture")
	flagLogErrors            = fs.Bool("log-errors", false, "enable verbose packet decoding error logging")
	flagFileStorage          = fs.String("fileStorage", "", "path to created extracted files (currently only for HTTP)")
	flagCalcEntropy          = fs.Bool("entropy", false, "enable entropy calculation for Eth,IP,TCP and UDP payloads")
	flagSnapLen              = fs.Int("snaplen", netcap.DefaultSnapLen, "configure snaplen for live capture from interface")
	flagVersion              = fs.Bool("version", false, "print netcap package version and exit")
	flagBaseLayer            = fs.String("base", "ethernet", "select base layer")
	flagDecodeOptions        = fs.String("opts", "lazy", "select decoding options")
	flagPayload              = fs.Bool("payload", false, "capture payload for supported layers")
	flagCompress             = fs.Bool("comp", true, "compress output with gzip")
	flagBuffer               = fs.Bool("buf", true, "buffer data in memory before writing to disk")
	flagOutDir               = fs.String("out", "", "specify output directory, will be created if it does not exist")
	flagBPF                  = fs.String("bpf", "", "supply a BPF filter to use prior to processing packets with netcap")
	flagInclude              = fs.String("include", "", "include specific decoders")
	flagExclude              = fs.String("exclude", "", "exclude specific decoders")
	flagMemProfile           = fs.Bool("memprof", false, "create memory profile")
	flagCSV                  = fs.Bool("csv", false, "print output data as csv with header line")
	flagContext              = fs.Bool("context", true, "add packet flow context to selected audit records")
	flagMemBufferSize        = fs.Int("membuf-size", netcap.DefaultBufferSize, "set size for membuf")
	flagListInterfaces       = fs.Bool("interfaces", false, "list all visible network interfaces")
	flagReverseDNS           = fs.Bool("reverse-dns", false, "resolve ips to domains via the operating systems default dns resolver")
	flagLocalDNS             = fs.Bool("local-dns", false, "resolve DNS locally via hosts file in the database dir")
	flagMACDB                = fs.Bool("macDB", false, "use mac to vendor database for device profiling")
	flagJa3DB                = fs.Bool("ja3DB", false, "use ja3 database for device profiling")
	flagServiceDB            = fs.Bool("serviceDB", false, "use serviceDB for device profiling")
	flagGeolocationDB        = fs.Bool("geoDB", false, "use geolocation for device profiling")
	flagDPI                  = fs.Bool("dpi", false, "use DPI for device profiling")
	flagFlushevery           = fs.Int("flushevery", netcap.DefaultFlushEvery, "flush assembler every N packets")
	flagDefragIPv4           = fs.Bool("ip4defrag", netcap.DefaultDefragIPv4, "Defragment IPv4 packets")
	flagChecksum             = fs.Bool("checksum", netcap.DefaultChecksum, "check TCP checksum")
	flagNooptcheck           = fs.Bool("nooptcheck", netcap.DefaultNoOptCheck, "do not check TCP options (useful to ignore MSS on captures with TSO)")
	flagIgnorefsmerr         = fs.Bool("ignorefsmerr", netcap.DefaultIgnoreFSMErr, "ignore TCP FSM errors")
	flagAllowmissinginit     = fs.Bool("allowmissinginit", netcap.DefaultAllowMissingInit, "support streams without SYN/SYN+ACK/ACK sequence")
	flagDebug                = fs.Bool("debug", false, "display debug information")
	flagHexdump              = fs.Bool("hexdump", false, "dump packets used in stream reassembly as hex to the reassembly.log file")
	flagWaitForConnections   = fs.Bool("wait-conns", true, "wait for all connections to finish processing before cleanup")
	flagWriteincomplete      = fs.Bool("writeincomplete", false, "write incomplete response")
	flagMemprofile           = fs.String("memprofile", "", "write memory profile")
	flagConnFlushInterval    = fs.Int("conn-flush-interval", netcap.DefaultConnFlushInterval, "flush connections every X flows")
	flagConnTimeOut          = fs.Duration("conn-timeout", netcap.DefaultConnTimeOut, "close connections older than X seconds")
	flagFlowFlushInterval    = fs.Int("flow-flush-interval", netcap.DefaultFlowFlushInterval, "flushes flows every X flows")
	flagFlowTimeOut          = fs.Duration("flow-timeout", netcap.DefaultFlowTimeOut, "closes flows older than flowTimeout")
	flagClosePendingTimeout  = fs.Duration("close-pending-timeout", netcap.DefaultClosePendingTimeout, "reassembly: close connections that have pending bytes after X")
	flagCloseInactiveTimeout = fs.Duration("close-inactive-timeout", netcap.DefaultCloseInactiveTimeout, "reassembly: close connections that are inactive after X")
)
