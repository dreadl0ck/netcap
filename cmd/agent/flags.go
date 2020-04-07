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

import "github.com/namsral/flag"

var (
	flagInterface = flag.String("iface", "en0", "interface")
	flagMaxSize   = flag.Int("max", 10*1024, "max size of packet") // max 65,507 bytes

	flagBPF      = flag.String("bpf", "", "supply a BPF filter to use for netcap collection")
	flagInclude  = flag.String("include", "", "include specific encoders")
	flagExclude  = flag.String("exclude", "", "exclude specific encoders")
	flagEncoders = flag.Bool("encoders", false, "show all available encoders")

	flagWorkers      = flag.Int("workers", 100, "number of encoder routines")
	flagPacketBuffer = flag.Int("pbuf", 0, "set packet buffer size")
	flagPromiscMode  = flag.Bool("promisc", true, "capture live in promisc mode")
	flagSnapLen      = flag.Int("snaplen", 1514, "configure snaplen for live capture")

	flagServerPubKey  = flag.String("pubkey", "", "path to the hex encoded server public key on disk")
	flagAddr          = flag.String("addr", "127.0.0.1:1335", "specify the address and port of the collection server")
	flagBaseLayer     = flag.String("base", "ethernet", "select base layer")
	flagDecodeOptions = flag.String("opts", "lazy", "select decoding options")
	flagPayload       = flag.Bool("payload", false, "capture payload for supported layers")
	flagVersion       = flag.Bool("version", false, "print netcap package version and exit")
	flagContext       = flag.Bool("context", true, "add packet flow context to selected audit records")

	flagMemBufferSize  = flag.Int("membuf-size", 1024*1024*10, "set size for membuf")
	flagListInterfaces = flag.Bool("interfaces", false, "list all visible network interfaces")
	flagReverseDNS     = flag.Bool("reverse-dns", false, "resolve ips to domains via the operating systems default dns resolver")
	flagLocalDNS       = flag.Bool("local-dns", false, "resolve DNS locally via hosts file in the database dir")
	flagMACDB          = flag.Bool("macDB", false, "use mac to vendor database for device profiling")
	flagJa3DB          = flag.Bool("ja3DB", false, "use ja3 database for device profiling")
	flagServiceDB      = flag.Bool("serviceDB", false, "use serviceDB for device profiling")
	flagGeolocationDB  = flag.Bool("geoDB", false, "use geolocation for device profiling")
	flagDPI            = flag.Bool("dpi", false, "use DPI for device profiling")
)
