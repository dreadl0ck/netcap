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

package config

import (
	"runtime"
	"sync"
	"time"

	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/io"
)

// Instance contains the config at runtime.
var Instance *Config

// DefaultConfig is a sane example configuration for the decoder package.
var DefaultConfig = &Config{
	Buffer:                     true,
	MemBufferSize:              defaults.BufferSize,
	Compression:                true,
	CSV:                        false,
	IncludeDecoders:            "",
	ExcludeDecoders:            "",
	Out:                        "",
	Chan:                       false,
	Proto:                      true,
	Source:                     "",
	IncludePayloads:            false,
	ExportMetrics:              false,
	AddContext:                 true,
	FlushEvery:                 100,
	DefragIPv4:                 false,
	Checksum:                   false,
	NoOptCheck:                 false,
	IgnoreFSMerr:               false,
	AllowMissingInit:           false,
	Debug:                      false,
	HexDump:                    false,
	WaitForConnections:         true,
	WriteIncomplete:            false,
	MemProfile:                 "",
	ConnFlushInterval:          10000,
	ConnTimeOut:                10 * time.Second,
	FlowFlushInterval:          2000,
	FlowTimeOut:                10 * time.Second,
	CloseInactiveTimeOut:       24 * time.Hour,
	ClosePendingTimeOut:        5 * time.Second,
	FileStorage:                defaults.FileStorage,
	CalculateEntropy:           false,
	SaveConns:                  false,
	TCPDebug:                   false,
	UseRE2:                     true,
	HarvesterBannerSize:        512,
	BannerSize:                 512,
	StopAfterHarvesterMatch:    true,
	StopAfterServiceProbeMatch: true,
	IgnoreDecoderInitErrors:    true,
	RemoveClosedStreams:        false,
	CompressionBlockSize:       defaults.CompressionBlockSize,
	CompressionLevel:           defaults.CompressionLevel,
	NumStreamWorkers:           runtime.NumCPU(),
	StreamBufferSize:           100,
}

// Config contains configuration parameters
// for the decoders
// this structure has an optimized field order to avoid excessive padding.
type Config struct {
	sync.Mutex

	// Output path
	Out string

	// Source of the audit records (pcap, live etc)
	Source string

	// CustomRegex to use for credentials harvester
	CustomRegex string

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
}
