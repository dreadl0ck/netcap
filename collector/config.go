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

package collector

import (
	"os"

	"github.com/dreadl0ck/gopacket"

	"github.com/dreadl0ck/netcap/decoder"
	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/utils"
)

// DefaultConfig is a sane example configuration.
//goland:noinspection GoUnusedGlobalVariable,GoUnnecessarilyExportedIdentifiers
var DefaultConfig = Config{
	Workers:             1000,
	PacketBufferSize:    100,
	WriteUnknownPackets: false,
	Promisc:             false,
	SnapLen:             defaults.SnapLen,
	DPI:                 false,
	BaseLayer:           utils.GetBaseLayer("ethernet"),
	DecodeOptions:       utils.GetDecodeOptions("datagrams"),
	Quiet:               false,
	DecoderConfig:       decoder.DefaultConfig,
	ResolverConfig:      resolvers.DefaultConfig,
	LogErrors:           false,
}

// DefaultConfigDPI is a sane example configuration for use with Deep Packet Inspection.
//goland:noinspection GoUnusedGlobalVariable,GoUnnecessarilyExportedIdentifiers
var DefaultConfigDPI = Config{
	Workers:             1000,
	PacketBufferSize:    100,
	WriteUnknownPackets: false,
	Promisc:             false,
	SnapLen:             defaults.SnapLen,
	DPI:                 true,
	BaseLayer:           utils.GetBaseLayer("ethernet"),
	DecodeOptions:       utils.GetDecodeOptions("datagrams"),
	Quiet:               false,
	DecoderConfig:       decoder.DefaultConfig,
	ResolverConfig:      resolvers.DefaultConfig,
	LogErrors:           false,
}

// Config contains configuration parameters
// for the Collector instance.
// this structure has an optimized field order to avoid excessive padding.
type Config struct {

	// Decoder configuration
	DecoderConfig *decoder.Config

	// Baselayer to start decoding from
	BaseLayer gopacket.LayerType

	// Number of workers to use
	Workers int

	// Size of the input buffer channels for the workers
	PacketBufferSize int

	// Ethernet frame snaplength for live capture
	SnapLen int

	// Can be used to periodically free OS memory
	FreeOSMem int

	// Permissions for output directory
	OutDirPermission os.FileMode

	// Attach in promiscuous mode for live capture
	Promisc bool

	// Controls whether packets that had an unknown layer will get written into a separate file
	WriteUnknownPackets bool

	// Resolver configuration
	ResolverConfig resolvers.Config

	// Decoding options for gopacket
	DecodeOptions gopacket.DecodeOptions

	// Dont print any output to the console
	Quiet bool

	// Enable deep packet inspection
	DPI bool

	// Use TCP reassembly
	ReassembleConnections bool

	// LogErrors will log verbose packet decoding errors into the errors.log file
	LogErrors bool

	// NoPrompt will disable all human interaction prompts
	NoPrompt bool

	// HTTPShutdownEndpoint will run a HTTP service on localhost:60589
	// sending a GET request there can be used to trigger teardown and audit record flushing
	// which can be used as alternative to using OS signals
	HTTPShutdownEndpoint bool
}
