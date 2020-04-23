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

package agent

import (
	"github.com/namsral/flag"
	"os"
	"runtime"
	"time"
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
	flagInterface      = fs.String("iface", "en0", "interface")
	flagMaxSize        = fs.Int("max", 10*1024, "max size of packet") // max 65,507 bytes

	flagBPF      = fs.String("bpf", "", "supply a BPF filter to use for netcap collection")
	flagInclude  = fs.String("include", "", "include specific encoders")
	flagExclude  = fs.String("exclude", "", "exclude specific encoders")
	flagEncoders = fs.Bool("encoders", false, "show all available encoders")

	flagWorkers      = fs.Int("workers", runtime.NumCPU(), "number of workers")
	flagPacketBuffer = fs.Int("pbuf", 0, "set packet buffer size")
	flagPromiscMode  = fs.Bool("promisc", true, "capture live in promisc mode")
	flagSnapLen      = fs.Int("snaplen", 1514, "configure snaplen for live capture")

	flagServerPubKey  = fs.String("pubkey", "", "path to the hex encoded server public key on disk")
	flagAddr          = fs.String("addr", "127.0.0.1:1335", "specify the address and port of the collection server")
	flagBaseLayer     = fs.String("base", "ethernet", "select base layer")
	flagDecodeOptions = fs.String("opts", "lazy", "select decoding options")
	flagPayload       = fs.Bool("payload", false, "capture payload for supported layers")
	flagVersion       = fs.Bool("version", false, "print netcap package version and exit")
	flagContext       = fs.Bool("context", true, "add packet flow context to selected audit records")

	flagMemBufferSize  = fs.Int("membuf-size", 1024*1024*10, "set size for membuf")
	flagListInterfaces = fs.Bool("interfaces", false, "list all visible network interfaces")
	flagReverseDNS     = fs.Bool("reverse-dns", false, "resolve ips to domains via the operating systems default dns resolver")
	flagLocalDNS       = fs.Bool("local-dns", false, "resolve DNS locally via hosts file in the database dir")
	flagMACDB          = fs.Bool("macDB", false, "use mac to vendor database for device profiling")
	flagJa3DB          = fs.Bool("ja3DB", false, "use ja3 database for device profiling")
	flagServiceDB      = fs.Bool("serviceDB", false, "use serviceDB for device profiling")
	flagGeolocationDB  = fs.Bool("geoDB", false, "use geolocation for device profiling")
	flagDPI            = fs.Bool("dpi", false, "use DPI for device profiling")

	flagFlushevery           = fs.Int("flushevery", 100, "flush assembler every N packets")
	flagNodefrag             = fs.Bool("nodefrag", false, "if true, do not do IPv4 defrag")
	flagChecksum             = fs.Bool("checksum", false, "check TCP checksum")
	flagNooptcheck           = fs.Bool("nooptcheck", false, "do not check TCP options (useful to ignore MSS on captures with TSO)")
	flagIgnorefsmerr         = fs.Bool("ignorefsmerr", false, "ignore TCP FSM errors")
	flagAllowmissinginit     = fs.Bool("allowmissinginit", false, "support streams without SYN/SYN+ACK/ACK sequence")
	flagDebug                = fs.Bool("debug", false, "display debug information")
	flagHexdump              = fs.Bool("hexdump-http", false, "dump HTTP request/response as hex")
	flagWaitForConnections   = fs.Bool("wait-conns", true, "wait for all connections to finish processing before cleanup")
	flagWriteincomplete      = fs.Bool("writeincomplete", false, "write incomplete response")
	flagMemprofile           = fs.String("memprofile", "", "write memory profile")
	flagConnFlushInterval    = fs.Int("conn-flush-interval", 10000, "flush connections every X flows")
	flagConnTimeOut          = fs.Duration("conn-timeout", 10*time.Second, "close connections older than X seconds")
	flagFlowFlushInterval    = fs.Int("flow-flush-interval", 2000, "flushes flows every X flows")
	flagFlowTimeOut          = fs.Duration("flow-timeout", 10*time.Second, "closes flows older than flowTimeout")
	flagClosePendingTimeout  = fs.Duration("close-pending-timeout", 5*time.Second, "reassembly: close connections that have pending bytes after X")
	flagCloseInactiveTimeout = fs.Duration("close-inactive-timeout", 24*time.Hour, "reassembly: close connections that are inactive after X")
)
