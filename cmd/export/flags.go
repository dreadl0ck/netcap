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

package export

import (
	"runtime"

	"github.com/urfave/cli/v3"

	"github.com/dreadl0ck/netcap/defaults"
)

// Flags returns all flag names for the export subcommand.
func Flags() []string {
	var flags []string
	for _, f := range GetFlags() {
		flags = append(flags, f.Names()[0])
	}
	return flags
}

// GetFlags returns the CLI flags for the export subcommand.
func GetFlags() []cli.Flag {
	return []cli.Flag{
		&cli.BoolFlag{
			Name:    "gen-config",
			Usage:   "generate config",
			Sources: cli.EnvVars("NC_GEN_CONFIG"),
		},
		&cli.StringFlag{
			Name:    "config",
			Usage:   "read configuration from file at path",
			Sources: cli.EnvVars("NC_CONFIG"),
		},
		&cli.StringFlag{
			Name:    "address",
			Value:   "127.0.0.1:7777",
			Usage:   "set address for exposing metrics",
			Sources: cli.EnvVars("NC_ADDRESS"),
		},
		&cli.BoolFlag{
			Name:    "dumpJson",
			Usage:   "dump as JSON",
			Sources: cli.EnvVars("NC_DUMPJSON"),
		},
		&cli.BoolFlag{
			Name:    "replay",
			Usage:   "replay traffic (only works when exporting audit records directly!)",
			Sources: cli.EnvVars("NC_REPLAY"),
		},
		&cli.StringFlag{
			Name:    "dir",
			Usage:   "path to directory with netcap audit records",
			Sources: cli.EnvVars("NC_DIR"),
		},
		&cli.StringFlag{
			Name:    "read",
			Usage:   "read specified file, can either be a pcap or netcap audit record file",
			Sources: cli.EnvVars("NC_READ"),
		},
		&cli.StringFlag{
			Name:    "iface",
			Usage:   "attach to network interface and capture in live mode",
			Sources: cli.EnvVars("NC_IFACE"),
		},
		&cli.IntFlag{
			Name:    "workers",
			Value:   runtime.NumCPU(),
			Usage:   "number of workers",
			Sources: cli.EnvVars("NC_WORKERS"),
		},
		&cli.IntFlag{
			Name:    "pbuf",
			Value:   defaults.PacketBuffer,
			Usage:   "set packet buffer size, for channels that feed data to workers",
			Sources: cli.EnvVars("NC_PBUF"),
		},
		&cli.BoolFlag{
			Name:    "ignore-unknown",
			Usage:   "disable writing unknown packets into a pcap file",
			Sources: cli.EnvVars("NC_IGNORE_UNKNOWN"),
		},
		&cli.BoolFlag{
			Name:    "promisc",
			Value:   true,
			Usage:   "toggle promiscuous mode for live capture",
			Sources: cli.EnvVars("NC_PROMISC"),
		},
		&cli.BoolFlag{
			Name:    "log-errors",
			Usage:   "enable verbose packet decoding error logging",
			Sources: cli.EnvVars("NC_LOG_ERRORS"),
		},
		&cli.StringFlag{
			Name:    "fileStorage",
			Value:   "files",
			Usage:   "path to created extracted files (relative to output directory, empty string disables file extraction, currently only for HTTP)",
			Sources: cli.EnvVars("NC_FILESTORAGE"),
		},
		&cli.BoolFlag{
			Name:    "entropy",
			Usage:   "enable entropy calculation for Eth,IP,TCP and UDP payloads",
			Sources: cli.EnvVars("NC_ENTROPY"),
		},
		&cli.IntFlag{
			Name:    "snaplen",
			Value:   defaults.SnapLen,
			Usage:   "configure snaplen for live capture from interface",
			Sources: cli.EnvVars("NC_SNAPLEN"),
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
		&cli.StringFlag{
			Name:    "out",
			Usage:   "specify output directory, will be created if it does not exist",
			Sources: cli.EnvVars("NC_OUT"),
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
			Name:    "memprof",
			Usage:   "create memory profile",
			Sources: cli.EnvVars("NC_MEMPROF"),
		},
		&cli.BoolFlag{
			Name:    "csv",
			Usage:   "print output data as csv with header line",
			Sources: cli.EnvVars("NC_CSV"),
		},
		&cli.BoolFlag{
			Name:    "context",
			Value:   true,
			Usage:   "add packet flow context to selected audit records",
			Sources: cli.EnvVars("NC_CONTEXT"),
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
			Usage:   "use mac to vendor database for device profiling",
			Sources: cli.EnvVars("NC_MACDB"),
		},
		&cli.BoolFlag{
			Name:    "ja4DB",
			Usage:   "use JA4+ database for TLS fingerprint lookups",
			Sources: cli.EnvVars("NC_JA4DB"),
		},
		&cli.BoolFlag{
			Name:    "serviceDB",
			Usage:   "use serviceDB for device profiling",
			Sources: cli.EnvVars("NC_SERVICEDB"),
		},
		&cli.BoolFlag{
			Name:    "geoDB",
			Usage:   "use geolocation for device profiling",
			Sources: cli.EnvVars("NC_GEODB"),
		},
		&cli.BoolFlag{
			Name:    "dpi",
			Usage:   "use DPI for device profiling",
			Sources: cli.EnvVars("NC_DPI"),
		},
		&cli.StringFlag{
			Name:    "dpi-modules",
			Usage:   "DPI modules to use (comma-separated: lpi,ndpi,go). If empty, all modules will be used",
			Sources: cli.EnvVars("NC_DPI_MODULES"),
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
			Name:    "debug",
			Usage:   "display debug information",
			Sources: cli.EnvVars("NC_DEBUG"),
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
		&cli.StringFlag{
			Name:    "memprofile",
			Usage:   "write memory profile",
			Sources: cli.EnvVars("NC_MEMPROFILE"),
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
			Usage:   "reassembly: close connections that have pending bytes after X",
			Sources: cli.EnvVars("NC_CLOSE_PENDING_TIMEOUT"),
		},
		&cli.DurationFlag{
			Name:    "close-inactive-timeout",
			Value:   defaults.CloseInactiveTimeout,
			Usage:   "reassembly: close connections that are inactive after X",
			Sources: cli.EnvVars("NC_CLOSE_INACTIVE_TIMEOUT"),
		},
	}
}
