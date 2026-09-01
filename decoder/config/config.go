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

package config

import (
	"runtime"
	"time"

	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/internal/performance"
	"sync"

	"github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/label/manager"
)

// Instance contains the config at runtime.
var Instance *Config

// instanceMu guards concurrent access to Instance's fields.
//
// This lock used to be a sync.Mutex embedded in Config itself, which made every
// value copy of a Config a copylocks violation -- `go vet` reported it on each
// run, and Clone carried a //nolint:govet that go vet does not honour, since
// that directive belongs to golangci-lint.
//
// It moved out here because it was only ever used to guard the global Instance
// (a single call site, reading Instance.Debug during reassembly cleanup), never
// an arbitrary Config value. Attaching it to the type meant all 72 fields
// dragged a lock through every copy to protect one global. Embedding it as a
// *sync.Mutex instead would have made the copy legal but left every Config
// literal one missed initialisation away from a nil-pointer panic on Lock.
var instanceMu sync.Mutex

// LockInstance guards reads and writes of Instance's fields.
func LockInstance() { instanceMu.Lock() }

// UnlockInstance releases the lock taken by LockInstance.
func UnlockInstance() { instanceMu.Unlock() }

// DefaultConfig is a sane example configuration for the decoder package.
var DefaultConfig = &Config{
	Buffer:                        true,
	MemBufferSize:                 defaults.BufferSize,
	Compression:                   true,
	CSV:                           false,
	IncludeDecoders:               "",
	ExcludeDecoders:               "",
	Out:                           "",
	Chan:                          false,
	Proto:                         true,
	Source:                        "",
	IncludePayloads:               false,
	ExportMetrics:                 false,
	AddContext:                    true,
	FlushEvery:                    100,
	DefragIPv4:                    false,
	Checksum:                      false,
	NoOptCheck:                    false,
	IgnoreFSMerr:                  false,
	AllowMissingInit:              false,
	Debug:                         false,
	HexDump:                       false,
	WaitForConnections:            true,
	WriteIncomplete:               false,
	MemProfile:                    "",
	ConnFlushInterval:             10000,
	ConnTimeOut:                   10 * time.Second,
	FlowFlushInterval:             2000,
	FlowTimeOut:                   10 * time.Second,
	CloseInactiveTimeOut:          24 * time.Hour,
	ClosePendingTimeOut:           5 * time.Second,
	FileStorage:                   defaults.FileStorage,
	CalculateEntropy:              false,
	SaveConns:                     false,
	TCPDebug:                      false,
	UseRE2:                        true,
	HarvesterBannerSize:           512,
	BannerSize:                    512,
	StopAfterHarvesterMatch:       true,
	HarvesterPortFilter:           true,
	StopAfterServiceProbeMatch:    true,
	IgnoreDecoderInitErrors:       true,
	RemoveClosedStreams:           false,
	CompressionBlockSize:          defaults.CompressionBlockSize,
	CompressionLevel:              defaults.CompressionLevel,
	NumStreamWorkers:              runtime.NumCPU(),
	StreamBufferSize:              100,
	MaxStreamBytes:                10485760, // 10MB per stream direction by default
	MaxBufferedPagesPerConnection: 0,        // unlimited by default
	MaxBufferedPagesTotal:         0,        // unlimited by default
}

// Config contains configuration parameters
// for the decoders
// this structure has an optimized field order to avoid excessive padding.
type Config struct {
	// Output path
	Out string

	// Source of the audit records (pcap, live etc)
	Source string

	// CustomRegex to use for credentials harvester
	CustomRegex string

	// HarvestersConfigPath is the path to the harvesters configuration file
	HarvestersConfigPath string

	// Will create a memory dump at the specified path for debugging and profiling
	MemProfile string

	// Comma separated list of decoders to include
	IncludeDecoders string

	// Comma separated list of decoders to exclude
	ExcludeDecoders string

	// If a path is set files will be extracted and written to the specified path
	FileStorage string

	// Number of packets to arrive until the connections are checked for timeouts
	ConnFlushInterval int

	// Size of buffer used for writing audit records to disk
	MemBufferSize int

	// Used to flush flows to disk whose last timestamp is flowTimeOut older than current packet
	FlowTimeOut time.Duration

	// size of the channel used to pass reassembled stream data to a stream decoder
	StreamDecoderBufSize int

	// Close inactive streams after
	CloseInactiveTimeOut time.Duration

	// Interval to apply connection flushes
	FlushEvery int

	// Maximum number of bytes of the client and server conversation to be used for the harvesters
	// This is a performance-critical setting that prevents harvesters from processing large data streams
	// (e.g., file transfers) which could cause excessive CPU and memory usage.
	// Default: 512 bytes - increase if credential detection is failing for protocols with longer auth sequences.
	// Recommended range: 512-8192 bytes depending on your use case.
	HarvesterBannerSize int

	// Maximum number of bytes stored as service banner
	BannerSize int

	// Close streams with pending bytes after
	ClosePendingTimeOut time.Duration

	// Number of packets to arrive until the flows are checked for timeouts
	FlowFlushInterval int

	// Used to flush connections to disk whose last timestamp is connTimeOut older than current packet
	ConnTimeOut time.Duration

	// Use the RE2 engine from the go standard library
	// if this is set to false an alternative regex engine that is compatible to the .NET syntax will be used for service banner detection
	UseRE2 bool

	// stop processing the conversation when the first credential harvester returns a result
	StopAfterHarvesterMatch bool

	// HarvesterPortFilter when enabled (default: true), only invokes harvesters on their configured ports
	// This prevents false positives from harvesters matching unrelated protocol traffic
	// Set to false to run all harvesters against all traffic (legacy behavior)
	HarvesterPortFilter bool

	// stop processing the conversation when the first service probe returns a result
	StopAfterServiceProbeMatch bool

	// when identifying a category for a service based on the port, stop matching banners when all probes for the category failed
	StopAfterServiceCategoryMiss bool

	// Buffer data before writing it to disk
	Buffer bool

	// Write incomplete HTTP responses to disk when extracting files
	WriteIncomplete bool

	// Write into channel (used for distributed collection)
	Chan bool

	// Size for the channel writer
	ChanSize int

	// Generate CSV instead of audit records
	CSV bool

	// UnixSocket will send data over unix sockets
	UnixSocket bool

	// Encode values when generating CSV
	Encode bool

	// Label values when generating CSV
	Label bool

	// Output length delimited protocol buffers
	Proto bool

	// Output data to elastic database
	Elastic bool

	// Additional elastic configuration options
	io.ElasticConfig

	// Elastic bulk sizes
	BulkSizeGoPacket int
	BulkSizeCustom   int

	// Output JSON
	JSON bool

	// Discard all data and write nothing to disk
	Null bool

	// Add context to supported audit records
	AddContext bool

	// Wait until all connections finished processing when receiving shutdown signal
	WaitForConnections bool

	// Dump packet contents as hex for debugging
	HexDump bool

	// Toggle debug mode
	Debug bool

	// TCP state machine allow missing init in three way handshake
	AllowMissingInit bool

	// Ignore TCP state machine errors
	IgnoreFSMerr bool

	// Calculate entropy for payloads in Ethernet and IP audit records
	CalculateEntropy bool

	// Save the entire raw TCP conversations for all tracked connections to disk
	SaveConns bool

	// Enable verbose TCP debug log messages in debug.log
	TCPDebug bool

	// Dont check TCP options
	NoOptCheck bool

	// Dont verify the packet checksums
	Checksum bool

	// Defragment IPv4 packets
	DefragIPv4 bool

	// ExportMetrics will export prometheus metrics
	ExportMetrics bool

	// Add payload data to supported audit records
	IncludePayloads bool

	// Compress data before writing it to disk with gzip
	Compression bool

	// IgnoreDecoderInitErrors allows to control whether to crash on Custom Decoder initialization errors (usually caused by missing database files)
	// and enables users to use the decoders even if the files are not present, while just logging an error to stdout.
	// If the init error does not allow the decoder to function at least partially,
	// fatal should be invoked in the init function to crash and indicate failure.
	IgnoreDecoderInitErrors bool

	// Dont print any output to the console
	Quiet bool

	// Force printing progress to stderr even in quiet mode
	PrintProgress bool

	// TCP/UDP StreamProcessors buffer size for input channel
	StreamBufferSize int

	// TCP/UDP StreamProcessors number of workers
	NumStreamWorkers int

	// DisableGenericVersionHarvester will not use the generic version string regex for the software harvester
	DisableGenericVersionHarvester bool

	// RemoveClosedStreams will remove streams that received a FIN or RST packet
	// if set to false it allows to witness further packets for the stream, e.g. FIN-ACK
	RemoveClosedStreams bool

	// CompressionBlockSize is the block size used for parallel compression
	CompressionBlockSize int

	// CompressionLevel is the compression level to use by default
	CompressionLevel int

	// MaxStreamBytes is the maximum number of bytes to reassemble from a single stream direction
	// before ignoring the stream for performance reasons. If <= 0, this is unlimited.
	// Default: 10485760 (10MB) to prevent excessive memory usage from large transfers.
	MaxStreamBytes int

	// MaxBufferedPagesPerConnection is the maximum number of pages (~1900 bytes each) to buffer
	// per connection for out-of-order packets. If <= 0, this is unlimited.
	// When exceeded, forces flush of oldest buffered packet. Default: 0 (unlimited)
	MaxBufferedPagesPerConnection int

	// MaxBufferedPagesTotal is the maximum total number of pages (~1900 bytes each) to buffer
	// across all connections for out-of-order packets. If <= 0, this is unlimited.
	// When exceeded, forces flush globally. Default: 0 (unlimited)
	MaxBufferedPagesTotal int

	// PerfTracker tracks performance metrics
	PerfTracker *performance.Tracker

	// LabelManager produces a label string per audit record when Label is true.
	// Decoders forward this to the io.WriterConfig they construct.
	// May be nil even when Label is true; in that case CSV writers will omit
	// the Category column from both header and rows, so output stays well-formed
	// but unlabeled.
	LabelManager *manager.LabelManager

	// ProtoSearchPaths contains directories to search for .proto schema files.
	// When set, the protobuf decoder resolves field names from schema definitions.
	ProtoSearchPaths []string

	// ProtoShowAlternatives enables multi-interpretation mode for unknown protobuf fields.
	// When true, fields include alternative type interpretations (e.g. varint as sint64, bool).
	ProtoShowAlternatives bool

	// ProtoMessageTypes maps port numbers to fully qualified protobuf message types.
	// Format: "port:package.MessageType" (e.g. "50051:tutorial.AddressBook").
	ProtoMessageTypes []string
}

// Clone returns a shallow copy of the receiver.
//
// Config used to embed a sync.Mutex, which made `dup := *c` here a copylocks
// violation -- reported by `go vet` on every run, and annotated with a
// //nolint:govet that go vet does not honour (that directive is golangci-lint's).
// The mutex was never locked anywhere in the tree: removing it makes the copy
// legal rather than merely excused, and Clone no longer has to reset anything.
//
// Callers wanting a mutable copy of an existing configuration (typically tests
// starting from DefaultConfig) should still use Clone rather than `cfg := *src`,
// so there is one place to change if Config ever gains a field that must not be
// shared between copies.
func (c *Config) Clone() *Config {
	if c == nil {
		return nil
	}

	dup := *c

	return &dup
}
