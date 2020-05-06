package netcap

import "time"

const (
	DefaultBufferSize           = 1024 * 1024 // 1MB
	DefaultFlushEvery           = 1000
	DefaultPacketBuffer         = 10
	DefaultSnapLen              = 1514
	DefaultConnFlushInterval    = 10000
	DefaultConnTimeOut          = 10 * time.Second
	DefaultFlowFlushInterval    = 20000
	DefaultFlowTimeOut          = 10 * time.Second
	DefaultClosePendingTimeout  = 3 * time.Second
	DefaultCloseInactiveTimeout = 5 * time.Second
	DefaultReassemblyTimeout    = 300 * time.Millisecond
	DefaultCompressionBlockSize = 1024 * 1024 // 1MB
	DefaultAllowMissingInit     = true
)
