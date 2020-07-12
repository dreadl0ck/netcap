package netcap

import (
	"compress/flate"
	"time"
)

const (
	DefaultBufferSize           = 1024 * 1024 * 10 // 10 MB
	DefaultFlushEvery           = 1000
	DefaultPacketBuffer         = 100
	DefaultSnapLen              = 1514
	DefaultConnFlushInterval    = 10000
	DefaultConnTimeOut          = 10 * time.Second
	DefaultFlowFlushInterval    = 20000
	DefaultFlowTimeOut          = 10 * time.Second
	DefaultClosePendingTimeout  = 3 * time.Second
	DefaultCloseInactiveTimeout = 5 * time.Second
	DefaultReassemblyTimeout    = 1 * time.Second
	DefaultCompressionBlockSize = 1024 * 1024 * 1 // 1 MB
	DefaultCompressionLevel     = flate.BestSpeed

	// TCP reassembly:
	// default settings are meant to be forgiving in terms of TCP state machine correctness
	// in order to capture as much information as possible.
	DefaultAllowMissingInit = true
	DefaultDefragIPv4       = true
	DefaultNoOptCheck       = true
	DefaultChecksum         = false
	DefaultIgnoreFSMErr     = true
)
