/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package capture

import (
	"runtime"
	"time"

	"github.com/urfave/cli/v3"

	"github.com/dreadl0ck/netcap/defaults"
)

// Flags returns all flag names.
func Flags() (flags []string) {
	for _, f := range GetFlags() {
		flags = append(flags, f.Names()[0])
	}
	return flags
}

// GetFlags returns the CLI flags for the capture subcommand.
func GetFlags() []cli.Flag {
	return []cli.Flag{
		&cli.BoolFlag{
			Name:    "gen-config",
			Usage:   "generate config",
			Sources: cli.EnvVars("NC_GEN_CONFIG"),
		},
		&cli.BoolFlag{
			Name:    "gen-elastic-indices",
			Usage:   "generate elastic indices and mapping",
			Sources: cli.EnvVars("NC_GEN_ELASTIC_INDICES"),
		},
		&cli.StringFlag{
			Name:    "config",
			Usage:   "read configuration from file at path",
			Sources: cli.EnvVars("NC_CONFIG"),
		},
		&cli.StringFlag{
			Name:    "read",
			Usage:   "read specified file, can either be a pcap or netcap audit record file",
			Sources: cli.EnvVars("NC_READ"),
		},
		&cli.StringFlag{
			Name:    "metrics",
			Usage:   "serve metrics at",
			Sources: cli.EnvVars("NC_METRICS"),
		},
		&cli.StringFlag{
			Name:    "out",
			Usage:   "specify output directory, will be created if it does not exist",
			Sources: cli.EnvVars("NC_OUT"),
		},
		&cli.DurationFlag{
			Name:    "timeout",
			Value:   1 * time.Second,
			Usage:   "set the timeout for live capture, providing a value of zero will be substituted with pcap.BlockForever.",
			Sources: cli.EnvVars("NC_TIMEOUT"),
		},
		&cli.StringFlag{
			Name:    "labels",
			Usage:   "path to attacks for labeling audit records",
			Sources: cli.EnvVars("NC_LABELS"),
		},
		&cli.DurationFlag{
			Name:    "scatter-duration",
			Value:   5 * time.Minute,
			Usage:   "interval for scatter chart",
			Sources: cli.EnvVars("NC_SCATTER_DURATION"),
		},
		&cli.BoolFlag{
			Name:    "scatter",
			Value:   true,
			Usage:   "generate a scatter plot for labeled audit records",
			Sources: cli.EnvVars("NC_SCATTER"),
		},
		&cli.BoolFlag{
			Name:    "pps",
			Usage:   "generate a line plot for throughput in packets per second",
			Sources: cli.EnvVars("NC_PPS"),
		},
		&cli.StringFlag{
			Name:    "bpf",
			Usage:   "supply a BPF filter to use prior to processing packets with netcap",
			Sources: cli.EnvVars("NC_BPF"),
		},
		&cli.StringFlag{
			Name:    "include",
			Usage:   "include specific decoders",
			Sources: cli.EnvVars("NC_INCLUDE"),
		},
		&cli.StringFlag{
			Name:    "exclude",
			Usage:   "exclude specific decoders",
			Sources: cli.EnvVars("NC_EXCLUDE"),
		},
		&cli.BoolFlag{
			Name:    "decoders",
			Usage:   "show all available decoders",
			Sources: cli.EnvVars("NC_DECODERS"),
		},
		&cli.BoolFlag{
			Name:    "overview",
			Usage:   "print a list of all available decoders and fields",
			Sources: cli.EnvVars("NC_OVERVIEW"),
		},
		&cli.StringFlag{
			Name:    "iface",
			Usage:   "attach to network interface and capture in live mode",
			Sources: cli.EnvVars("NC_IFACE"),
		},
		&cli.BoolFlag{
			Name:    "compress",
			Value:   true,
			Usage:   "compress output with gzip",
			Sources: cli.EnvVars("NC_COMPRESS"),
		},
		&cli.BoolFlag{
			Name:    "buf",
			Value:   true,
			Usage:   "buffer data in memory before writing to disk",
			Sources: cli.EnvVars("NC_BUF"),
		},
		&cli.IntFlag{
			Name:    "workers",
			Value:   runtime.NumCPU() * 2,
			Usage:   "number of workers",
			Sources: cli.EnvVars("NC_WORKERS"),
		},
		&cli.IntFlag{
			Name:    "pbuf",
			Value:   defaults.PacketBuffer,
			Usage:   "set packet buffer size, for channels that feed data to workers",
			Sources: cli.EnvVars("NC_PBUF"),
		},
		&cli.StringFlag{
			Name:    "analyzer",
			Usage:   "the analyzer to use",
			Sources: cli.EnvVars("NC_ANALYZER"),
		},
		&cli.BoolFlag{
			Name:    "cpuprof",
			Usage:   "create cpu profile",
			Sources: cli.EnvVars("NC_CPUPROF"),
		},
		&cli.BoolFlag{
			Name:    "memprof",
			Usage:   "create memory profile",
			Sources: cli.EnvVars("NC_MEMPROF"),
		},
		&cli.BoolFlag{
			Name:    "ignore-unknown",
			Value:   true,
			Usage:   "disable writing unknown packets into a pcap file",
			Sources: cli.EnvVars("NC_IGNORE_UNKNOWN"),
		},
		&cli.BoolFlag{
			Name:    "promisc",
			Value:   true,
			Usage:   "toggle promiscuous mode for live capture",
			Sources: cli.EnvVars("NC_PROMISC"),
		},
		&cli.IntFlag{
			Name:    "snaplen",
			Value:   defaults.SnapLen,
			Usage:   "configure snaplen for live capture from interface",
			Sources: cli.EnvVars("NC_SNAPLEN"),
		},
		&cli.BoolFlag{
			Name:    "time",
			Usage:   "print processing time even in quiet mode",
			Sources: cli.EnvVars("NC_TIME"),
		},
		&cli.StringFlag{
			Name:    "base",
			Value:   "ethernet",
			Usage:   "select base layer",
			Sources: cli.EnvVars("NC_BASE"),
		},
		&cli.StringFlag{
			Name:    "opts",
			Value:   "default",
			Usage:   "select decoding options",
			Sources: cli.EnvVars("NC_OPTS"),
		},
		&cli.BoolFlag{
			Name:    "payload",
			Usage:   "capture payload for supported layers",
			Sources: cli.EnvVars("NC_PAYLOAD"),
		},
		&cli.BoolFlag{
			Name:    "csv",
			Usage:   "output data as CSV",
			Sources: cli.EnvVars("NC_CSV"),
		},
		&cli.BoolFlag{
			Name:    "unix",
			Usage:   "output data via unix sockets",
			Sources: cli.EnvVars("NC_UNIX"),
		},
		&cli.BoolFlag{
			Name:    "null",
			Usage:   "write no data to disk",
			Sources: cli.EnvVars("NC_NULL"),
		},
		&cli.BoolFlag{
			Name:    "elastic",
			Usage:   "write data to elastic db",
			Sources: cli.EnvVars("NC_ELASTIC"),
		},
		&cli.StringFlag{
			Name:    "elastic-addrs",
			Usage:   "elastic db endpoints to write data to",
			Sources: cli.EnvVars("NC_ELASTIC_ADDRS"),
		},
		&cli.StringFlag{
			Name:    "elastic-user",
			Usage:   "elastic db username",
			Sources: cli.EnvVars("NC_ELASTIC_USER"),
		},
		&cli.StringFlag{
			Name:    "elastic-pass",
			Usage:   "elastic db password",
			Sources: cli.EnvVars("NC_ELASTIC_PASS"),
		},
		&cli.IntFlag{
			Name:    "elastic-bulk-gopacket",
			Value:   2000,
			Usage:   "elastic bulk size for gopacket audit records",
			Sources: cli.EnvVars("NC_ELASTIC_BULK_GOPACKET"),
		},
		&cli.IntFlag{
			Name:    "elastic-bulk-custom",
			Value:   1000,
			Usage:   "elastic bulk size for custom audit records",
			Sources: cli.EnvVars("NC_ELASTIC_BULK_CUSTOM"),
		},
		&cli.StringFlag{
			Name:    "kibana",
			Usage:   "kibana endpoint URL",
			Sources: cli.EnvVars("NC_KIBANA"),
		},
		&cli.BoolFlag{
			Name:    "proto",
			Value:   true,
			Usage:   "output data as protobuf",
			Sources: cli.EnvVars("NC_PROTO"),
		},
		&cli.BoolFlag{
			Name:    "json",
			Usage:   "output data as JSON",
			Sources: cli.EnvVars("NC_JSON"),
		},
		&cli.BoolFlag{
			Name:    "context",
			Value:   true,
			Usage:   "add packet flow context to selected audit records",
			Sources: cli.EnvVars("NC_CONTEXT"),
		},
		&cli.BoolFlag{
			Name:    "http-shutdown",
			Usage:   "create local endpoint to trigger teardown via HTTP",
			Sources: cli.EnvVars("NC_HTTP_SHUTDOWN"),
		},
		&cli.IntFlag{
			Name:    "membuf-size",
			Value:   defaults.BufferSize,
			Usage:   "set size for membuf",
			Sources: cli.EnvVars("NC_MEMBUF_SIZE"),
		},
		&cli.BoolFlag{
			Name:    "interfaces",
			Usage:   "list all visible network interfaces",
			Sources: cli.EnvVars("NC_INTERFACES"),
		},
		&cli.BoolFlag{
			Name:    "quiet",
			Usage:   "don't print infos to stdout",
			Sources: cli.EnvVars("NC_QUIET"),
		},
		&cli.BoolFlag{
			Name:    "progress",
			Usage:   "force printing progress to stderr even in quiet mode",
			Sources: cli.EnvVars("NC_PROGRESS"),
		},
		&cli.StringFlag{
			Name:    "fileStorage",
			Value:   "files",
			Usage:   "path to extracted files (relative to output directory, empty string disables file extraction)",
			Sources: cli.EnvVars("NC_FILESTORAGE"),
		},
		&cli.StringFlag{
			Name:    "file-config",
			Usage:   "path to file extraction configuration YAML file",
			Sources: cli.EnvVars("NC_FILE_CONFIG"),
		},
		&cli.BoolFlag{
			Name:    "reverse-dns",
			Usage:   "resolve ips to domains via the operating systems default dns resolver",
			Sources: cli.EnvVars("NC_REVERSE_DNS"),
		},
		&cli.BoolFlag{
			Name:    "local-dns",
			Usage:   "resolve DNS locally via hosts file in the database dir",
			Sources: cli.EnvVars("NC_LOCAL_DNS"),
		},
		&cli.BoolFlag{
			Name:    "macDB",
			Value:   true,
			Usage:   "use mac to vendor database for device profiling",
			Sources: cli.EnvVars("NC_MACDB"),
		},
		&cli.BoolFlag{
			Name:    "ja4DB",
			Value:   true,
			Usage:   "use JA4+ database for TLS fingerprint lookups",
			Sources: cli.EnvVars("NC_JA4DB"),
		},
		&cli.BoolFlag{
			Name:    "serviceDB",
			Value:   true,
			Usage:   "use serviceDB for device profiling",
			Sources: cli.EnvVars("NC_SERVICEDB"),
		},
		&cli.BoolFlag{
			Name:    "geoDB",
			Value:   true,
			Usage:   "use geolocation for device profiling",
			Sources: cli.EnvVars("NC_GEODB"),
		},
		&cli.BoolFlag{
			Name:    "dpi",
			Value:   true,
			Usage:   "use DPI libs to enrich IPProfile audit records",
			Sources: cli.EnvVars("NC_DPI"),
		},
		&cli.StringFlag{
			Name:    "dpi-modules",
			Usage:   "DPI modules to use (comma-separated: lpi,ndpi,go). If empty, all modules will be used",
			Sources: cli.EnvVars("NC_DPI_MODULES"),
		},
		&cli.IntFlag{
			Name:    "free-os-mem",
			Usage:   "free OS memory every X minutes, disabled if set to 0",
			Sources: cli.EnvVars("NC_FREE_OS_MEM"),
		},
		&cli.BoolFlag{
			Name:    "reassemble-connections",
			Value:   true,
			Usage:   "reassemble TCP connections",
			Sources: cli.EnvVars("NC_REASSEMBLE_CONNECTIONS"),
		},
		&cli.BoolFlag{
			Name:    "tcp-debug",
			Usage:   "add debug output for TCP connections to debug.log",
			Sources: cli.EnvVars("NC_TCP_DEBUG"),
		},
		&cli.BoolFlag{
			Name:    "conns",
			Usage:   "save raw TCP connections",
			Sources: cli.EnvVars("NC_CONNS"),
		},
		&cli.BoolFlag{
			Name:    "entropy",
			Usage:   "enable entropy calculation for Eth,IP,TCP and UDP payloads",
			Sources: cli.EnvVars("NC_ENTROPY"),
		},
		&cli.BoolFlag{
			Name:    "log-errors",
			Usage:   "enable verbose packet decoding error logging",
			Sources: cli.EnvVars("NC_LOG_ERRORS"),
		},
		&cli.IntFlag{
			Name:    "flushevery",
			Value:   defaults.FlushEvery,
			Usage:   "flush assembler every N packets",
			Sources: cli.EnvVars("NC_FLUSHEVERY"),
		},
		&cli.BoolFlag{
			Name:    "ip4defrag",
			Value:   defaults.DefragIPv4,
			Usage:   "Defragment IPv4 packets",
			Sources: cli.EnvVars("NC_IP4DEFRAG"),
		},
		&cli.BoolFlag{
			Name:    "checksum",
			Value:   defaults.Checksum,
			Usage:   "check TCP checksum",
			Sources: cli.EnvVars("NC_CHECKSUM"),
		},
		&cli.BoolFlag{
			Name:    "nooptcheck",
			Value:   defaults.NoOptCheck,
			Usage:   "do not check TCP options (useful to ignore MSS on captures with TSO)",
			Sources: cli.EnvVars("NC_NOOPTCHECK"),
		},
		&cli.BoolFlag{
			Name:    "ignorefsmerr",
			Value:   defaults.IgnoreFSMErr,
			Usage:   "ignore TCP FSM errors",
			Sources: cli.EnvVars("NC_IGNOREFSMERR"),
		},
		&cli.BoolFlag{
			Name:    "allowmissinginit",
			Value:   defaults.AllowMissingInit,
			Usage:   "support streams without SYN/SYN+ACK/ACK sequence",
			Sources: cli.EnvVars("NC_ALLOWMISSINGINIT"),
		},
		&cli.BoolFlag{
			Name:    "hexdump",
			Usage:   "dump packets used in stream reassembly as hex to the reassembly.log file",
			Sources: cli.EnvVars("NC_HEXDUMP"),
		},
		&cli.BoolFlag{
			Name:    "wait-conns",
			Value:   true,
			Usage:   "wait for all connections to finish processing before cleanup",
			Sources: cli.EnvVars("NC_WAIT_CONNS"),
		},
		&cli.BoolFlag{
			Name:    "writeincomplete",
			Usage:   "write incomplete response",
			Sources: cli.EnvVars("NC_WRITEINCOMPLETE"),
		},
		&cli.IntFlag{
			Name:    "sbuf-size",
			Value:   10,
			Usage:   "size for channel used to pass data to the stream decoders. default is unbuffered",
			Sources: cli.EnvVars("NC_SBUF_SIZE"),
		},
		&cli.BoolFlag{
			Name:    "reassembly-debug",
			Usage:   "if true, the reassembly will log verbose debugging information",
			Sources: cli.EnvVars("NC_REASSEMBLY_DEBUG"),
		},
		&cli.BoolFlag{
			Name:    "y",
			Usage:   "answer yes to all prompts",
			Sources: cli.EnvVars("NC_Y"),
		},
		&cli.BoolFlag{
			Name:    "debug",
			Usage:   "display debug information",
			Sources: cli.EnvVars("NC_DEBUG"),
		},
		&cli.StringFlag{
			Name:    "memprofile",
			Usage:   "write memory profile",
			Sources: cli.EnvVars("NC_MEMPROFILE"),
		},
		&cli.StringFlag{
			Name:    "pprof",
			Usage:   "start pprof HTTP server on specified address (e.g., localhost:6060)",
			Sources: cli.EnvVars("NC_PPROF"),
		},
		&cli.IntFlag{
			Name:    "conn-flush-interval",
			Value:   defaults.ConnFlushInterval,
			Usage:   "flush connections every X flows",
			Sources: cli.EnvVars("NC_CONN_FLUSH_INTERVAL"),
		},
		&cli.DurationFlag{
			Name:    "conn-timeout",
			Value:   defaults.ConnTimeOut,
			Usage:   "close connections older than X seconds",
			Sources: cli.EnvVars("NC_CONN_TIMEOUT"),
		},
		&cli.IntFlag{
			Name:    "flow-flush-interval",
			Value:   defaults.FlowFlushInterval,
			Usage:   "flushes flows every X flows",
			Sources: cli.EnvVars("NC_FLOW_FLUSH_INTERVAL"),
		},
		&cli.DurationFlag{
			Name:    "flow-timeout",
			Value:   defaults.FlowTimeOut,
			Usage:   "closes flows older than flowTimeout",
			Sources: cli.EnvVars("NC_FLOW_TIMEOUT"),
		},
		&cli.DurationFlag{
			Name:    "close-pending-timeout",
			Value:   defaults.ClosePendingTimeout,
			Usage:   "reassembly: close connections that have pending bytes",
			Sources: cli.EnvVars("NC_CLOSE_PENDING_TIMEOUT"),
		},
		&cli.DurationFlag{
			Name:    "close-inactive-timeout",
			Value:   defaults.CloseInactiveTimeout,
			Usage:   "reassembly: close connections that are inactive",
			Sources: cli.EnvVars("NC_CLOSE_INACTIVE_TIMEOUT"),
		},
		&cli.BoolFlag{
			Name:    "re2",
			Value:   true,
			Usage:   "if true uses the default golang re2 regex engine for service detection",
			Sources: cli.EnvVars("NC_RE2"),
		},
		&cli.BoolFlag{
			Name:    "stop-after-harvester-match",
			Value:   true,
			Usage:   "stop processing the conversation after the first credential harvester returned a result",
			Sources: cli.EnvVars("NC_STOP_AFTER_HARVESTER_MATCH"),
		},
		&cli.BoolFlag{
			Name:    "stop-after-service-match",
			Value:   true,
			Usage:   "stop processing the conversation after the first service probe returned a result",
			Sources: cli.EnvVars("NC_STOP_AFTER_SERVICE_MATCH"),
		},
		&cli.BoolFlag{
			Name:    "stop-after-service-category-miss",
			Value:   true,
			Usage:   "stop processing the conversation after the first service probe returned a result",
			Sources: cli.EnvVars("NC_STOP_AFTER_SERVICE_CATEGORY_MISS"),
		},
		&cli.BoolFlag{
			Name:    "ignore-init-errors",
			Value:   true,
			Usage:   "ignore errors from initializing custom decoders",
			Sources: cli.EnvVars("NC_IGNORE_INIT_ERRORS"),
		},
		&cli.BoolFlag{
			Name:    "disable-generic-software-harvester",
			Value:   true,
			Usage:   "disable the generic software harvester regex",
			Sources: cli.EnvVars("NC_DISABLE_GENERIC_SOFTWARE_HARVESTER"),
		},
		&cli.BoolFlag{
			Name:    "remove-closed-streams",
			Usage:   "remove tcp streams that receive a FIN or RST packet from the stream pool",
			Sources: cli.EnvVars("NC_REMOVE_CLOSED_STREAMS"),
		},
		&cli.BoolFlag{
			Name:    "encode",
			Usage:   "encode data written into CSV file",
			Sources: cli.EnvVars("NC_ENCODE"),
		},
		&cli.IntFlag{
			Name:    "bsize",
			Value:   256,
			Usage:   "size of the stored service banners in bytes",
			Sources: cli.EnvVars("NC_BSIZE"),
		},
		&cli.IntFlag{
			Name:    "hbsize",
			Value:   256,
			Usage:   "max bytes per stream passed to credential harvesters (prevents processing large file transfers, recommended: 512-8192)",
			Sources: cli.EnvVars("NC_HBSIZE"),
		},
		&cli.StringFlag{
			Name:    "reCustom",
			Usage:   "possibility of passing a custom regex for harvesting credentials",
			Sources: cli.EnvVars("NC_RECUSTOM"),
		},
		&cli.StringFlag{
			Name:    "harvesters-config",
			Usage:   "path to harvesters configuration YAML file",
			Sources: cli.EnvVars("NC_HARVESTERS_CONFIG"),
		},
		&cli.IntFlag{
			Name:    "stream-buffer",
			Value:   10,
			Usage:   "input channel size for TCP / UDP stream processors",
			Sources: cli.EnvVars("NC_STREAM_BUFFER"),
		},
		&cli.IntFlag{
			Name:    "stream-workers",
			Value:   runtime.NumCPU(),
			Usage:   "number of TCP / UDP stream workers",
			Sources: cli.EnvVars("NC_STREAM_WORKERS"),
		},
		&cli.IntFlag{
			Name:    "max-stream-bytes",
			Value:   10485760,
			Usage:   "maximum number of bytes to reassemble per stream direction (0 = unlimited, default = 10MB)",
			Sources: cli.EnvVars("NC_MAX_STREAM_BYTES"),
		},
		&cli.IntFlag{
			Name:    "max-buffered-pages-per-conn",
			Usage:   "maximum pages to buffer per connection for out-of-order packets (0 = unlimited, ~1900 bytes per page)",
			Sources: cli.EnvVars("NC_MAX_BUFFERED_PAGES_PER_CONN"),
		},
		&cli.IntFlag{
			Name:    "max-buffered-pages-total",
			Usage:   "maximum total pages to buffer across all connections (0 = unlimited, ~1900 bytes per page)",
			Sources: cli.EnvVars("NC_MAX_BUFFERED_PAGES_TOTAL"),
		},
		&cli.IntFlag{
			Name:    "compression-block-size",
			Value:   defaults.CompressionBlockSize,
			Usage:   "block size used for parallel compression",
			Sources: cli.EnvVars("NC_COMPRESSION_BLOCK_SIZE"),
		},
		&cli.StringFlag{
			Name:    "compression-level",
			Value:   "default",
			Usage:   "level of compression",
			Sources: cli.EnvVars("NC_COMPRESSION_LEVEL"),
		},
		&cli.StringFlag{
			Name:    "http",
			Value:   "localhost:8080",
			Usage:   "start web UI server on specified address (e.g., localhost:8080)",
			Sources: cli.EnvVars("NC_HTTP"),
		},
		&cli.StringFlag{
			Name:    "http-assets",
			Usage:   "path to custom frontend assets (for development)",
			Sources: cli.EnvVars("NC_HTTP_ASSETS"),
		},
		&cli.BoolFlag{
			Name:    "service",
			Usage:   "run in service mode for multi-file upload and analysis",
			Sources: cli.EnvVars("NC_SERVICE"),
		},
		&cli.StringFlag{
			Name:    "service-data-dir",
			Usage:   "directory for service mode uploads and results (default: auto-detect)",
			Sources: cli.EnvVars("NC_SERVICE_DATA_DIR"),
		},
		&cli.Int64Flag{
			Name:    "service-max-file-size",
			Value:   100 * 1024 * 1024,
			Usage:   "maximum upload file size in bytes for service mode (default: 100MB)",
			Sources: cli.EnvVars("NC_SERVICE_MAX_FILE_SIZE"),
		},
		&cli.IntFlag{
			Name:    "service-max-per-hour",
			Value:   10,
			Usage:   "maximum number of analyses per IP per hour in service mode (default: 10, 0 = unlimited)",
			Sources: cli.EnvVars("NC_SERVICE_MAX_PER_HOUR"),
		},
		&cli.IntFlag{
			Name:    "service-expiry",
			Value:   60,
			Usage:   "session expiry time in minutes for service mode",
			Sources: cli.EnvVars("NC_SERVICE_EXPIRY"),
		},
		&cli.IntFlag{
			Name:    "service-cleanup",
			Value:   10,
			Usage:   "cleanup check interval in minutes for service mode",
			Sources: cli.EnvVars("NC_SERVICE_CLEANUP"),
		},
		&cli.Int64Flag{
			Name:    "service-max-storage",
			Value:   10 * 1024 * 1024 * 1024,
			Usage:   "maximum total storage in bytes for service mode (default: 10GB, 0 = unlimited)",
			Sources: cli.EnvVars("NC_SERVICE_MAX_STORAGE"),
		},
		&cli.IntFlag{
			Name:    "service-preload-largest-n",
			Value:   20,
			Usage:   "load only the N largest files from pcaps folder (default: 0 = all files)",
			Sources: cli.EnvVars("NC_SERVICE_PRELOAD_LARGEST_N"),
		},
		&cli.BoolFlag{
			Name:    "service-enforce-max-size-preload",
			Usage:   "enforce service max file size for preloaded pcaps in pcaps folder",
			Sources: cli.EnvVars("NC_SERVICE_ENFORCE_MAX_SIZE_PRELOAD"),
		},
		&cli.StringFlag{
			Name:    "filter",
			Usage:   "filter audit records using an expr-lang expression (e.g., 'DstPort == 443')",
			Sources: cli.EnvVars("NC_FILTER"),
		},
		&cli.StringFlag{
			Name:    "rules",
			Usage:   "path to rules file for alert generation (YAML format)",
			Sources: cli.EnvVars("NC_RULES"),
		},
		&cli.BoolFlag{
			Name:    "dev",
			Usage:   "development mode: use current binary instead of 'net' for job execution",
			Sources: cli.EnvVars("NC_DEV"),
		},
	}
}
