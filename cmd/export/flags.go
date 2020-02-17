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
	flagMetricsAddress = flag.String("address", "127.0.0.1:7777", "set address for exposing metrics")
	flagDumpJSON       = flag.Bool("dumpJson", false, "dump as JSON")
	flagReplay         = flag.Bool("replay", false, "replay traffic (only works when exporting audit records directly!)")
	flagDir            = flag.String("dir", "", "path to directory with netcap audit records")
	flagInput          = flag.String("r", "", "read specified file, can either be a pcap or netcap audit record file")
	flagInterface      = flag.String("iface", "", "attach to network interface and capture in live mode")
	flagWorkers        = flag.Int("workers", 1000, "number of workers")
	flagPacketBuffer   = flag.Int("pbuf", 100, "set packet buffer size, for channels that feed data to workers")
	flagIngoreUnknown  = flag.Bool("ignore-unknown", false, "disable writing unknown packets into a pcap file")
	flagPromiscMode    = flag.Bool("promisc", true, "toggle promiscous mode for live capture")
	flagSnapLen        = flag.Int("snaplen", 1514, "configure snaplen for live capture from interface")
	flagVersion        = flag.Bool("version", false, "print netcap package version and exit")
	flagBaseLayer      = flag.String("base", "ethernet", "select base layer")
	flagDecodeOptions  = flag.String("opts", "lazy", "select decoding options")
	flagPayload        = flag.Bool("payload", false, "capture payload for supported layers")
	flagCompress       = flag.Bool("comp", true, "compress output with gzip")
	flagBuffer         = flag.Bool("buf", true, "buffer data in memory before writing to disk")
	flagOutDir         = flag.String("out", "", "specify output directory, will be created if it does not exist")
	flagBPF            = flag.String("bpf", "", "supply a BPF filter to use prior to processing packets with netcap")
	flagInclude        = flag.String("include", "", "include specific encoders")
	flagExclude        = flag.String("exclude", "LinkFlow,TransportFlow,NetworkFlow", "exclude specific encoders")
	flagMemProfile     = flag.Bool("memprof", false, "create memory profile")
	flagCSV            = flag.Bool("csv", false, "print output data as csv with header line")
	flagContext        = flag.Bool("context", true, "add packet flow context to selected audit records")
	flagMemBufferSize  = flag.Int("membuf-size", 1024*1024*10, "set size for membuf")
)
