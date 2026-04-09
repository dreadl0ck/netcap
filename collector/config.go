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

package collector

import (
	"os"
	"runtime"
	"time"

	"github.com/gopacket/gopacket/pcap"

	"github.com/gopacket/gopacket"

	"github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/utils"
)

// defaultWorkers returns a CPU-proportional worker count.
func defaultWorkers() int {
	n := runtime.NumCPU() * 4
	if n < 4 {
		n = 4
	}
	return n
}

// DefaultConfig is a sane example configuration.
//
//goland:noinspection GoUnusedGlobalVariable,GoUnnecessarilyExportedIdentifiers
var DefaultConfig = Config{
	Workers:             0, // 0 means use defaultWorkers() at init time
	PacketBufferSize:    1000,
	WriteUnknownPackets: false,
	Promisc:             false,
	SnapLen:             defaults.SnapLen,
	DPI:                 false,
	BaseLayer:           utils.GetBaseLayer("ethernet"),
	DecodeOptions:       utils.GetDecodeOptions("default"),
	DecoderConfig:       config.DefaultConfig,
	ResolverConfig:      resolvers.DefaultConfig,
	Timeout:             pcap.BlockForever,
	LogErrors:           false,
}

// DefaultConfigDPI is a sane example configuration for use with Deep Packet Inspection.
//
//goland:noinspection GoUnusedGlobalVariable,GoUnnecessarilyExportedIdentifiers
var DefaultConfigDPI = Config{
	Workers:             0, // 0 means use defaultWorkers() at init time
	PacketBufferSize:    1000,
	WriteUnknownPackets: false,
	Promisc:             false,
	SnapLen:             defaults.SnapLen,
	DPI:                 true,
	BaseLayer:           utils.GetBaseLayer("ethernet"),
	DecodeOptions:       utils.GetDecodeOptions("default"),
	DecoderConfig:       config.DefaultConfig,
	ResolverConfig:      resolvers.DefaultConfig,
	LogErrors:           false,
}

// Config contains configuration parameters
// for the Collector instance.
// this structure has an optimized field order to avoid excessive padding.
type Config struct {

	// Decoder configuration
	DecoderConfig *config.Config

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

	// Enable deep packet inspection
	DPI bool

	// DPI modules to use (comma-separated: lpi, ndpi, go)
	// If empty and DPI is enabled, all modules will be used
	DPIModules string

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

	// NoSignalHandling disables signal handling in the collector
	// This is useful when running in service mode where the parent process handles signals
	NoSignalHandling bool

	// Timeout for live capture
	// if you set this to 0, the pcap.BlockForever option will be used
	// From the macOS docs on libpcap:
	//   The read timeout is used to arrange that the read not necessarily return
	//   immediately when a packet is seen, but that it wait for some amount of time
	//   to allow more packets to arrive and to read multiple packets from the OS
	//   kernel in one operation.
	Timeout time.Duration

	// Labels is a filesystem path to the labels file on disk
	// that contains the attack mappings
	Labels string

	// Generate scatter chart for the applied labels during labeling.
	Scatter bool

	// ScatterDuration is the interval for data used in the scatter plot.
	ScatterDuration time.Duration

	// LiveFlushInterval is the interval at which audit records are flushed during live capture.
	// This makes data visible while capture is ongoing.
	// If zero, no periodic flushing is performed (records only flushed on shutdown).
	// Recommended: 30s to 60s for most use cases.
	LiveFlushInterval time.Duration
}
