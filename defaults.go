package netcap

import (
	"compress/flate"
	"time"
)

const (
	// Size for memory buffering before feeding data into compressor
	DefaultBufferSize = 1024 * 1024 * 12 // 12 MB

	// Size of the channel for feeding packets into workers
	DefaultPacketBuffer = 100

	// Default snap length for an ethernet frame:
	// 1500 Ethernet MTU + 14 bytes Ethernet header
	DefaultSnapLen = 1514

	// Settings for Flow and Connection audit record generation
	// TODO: refactor to flush periodically, instead of every n packets?
	DefaultConnFlushInterval = 0
	DefaultFlowFlushInterval = 0

	// will be used to set age threshold if the corresponding FlushInterval > 0
	DefaultConnTimeOut = 0 * time.Second
	DefaultFlowTimeOut = 0 * time.Second

	// Compression Settings
	DefaultCompressionBlockSize = 1024 * 1024 * 1 // 1 MB
	DefaultCompressionLevel     = flate.BestSpeed

	// TCP Stream Reassembly:
	// default settings are meant to be forgiving in terms of TCP state machine correctness
	// in order to capture as much information as possible.

	// How long to wait for remaining open streams to close, before initiating teardown
	DefaultReassemblyTimeout = 5 * time.Second

	// TODO: refactor to flush periodically, instead of every n packets?
	// controls how often collected reassembly data is flushed to consumers
	DefaultFlushEvery = 100

	// Close streams with pending bytes after
	DefaultClosePendingTimeout = 1 * time.Hour

	// Close inactive streams after
	DefaultCloseInactiveTimeout = 1 * time.Hour

	// TCP State Machine
	DefaultAllowMissingInit = true
	DefaultDefragIPv4       = true
	DefaultNoOptCheck       = true
	DefaultChecksum         = false
	DefaultIgnoreFSMErr     = true
)
