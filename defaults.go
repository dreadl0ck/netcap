package netcap

import "time"

const (
	DefaultBufferSize           = 1024 * 1024 // 1MB
	DefaultFlushEvery           = 100
	DefaultPacketBuffer         = 10
	DefaultSnapLen              = 1514
	DefaultConnFlushInterval    = 10000
	DefaultConnTimeOut          = 10 * time.Second
	DefaultFlowFlushInterval    = 2000
	DefaultFlowTimeOut          = 10 * time.Second
	DefaultClosePendingTimeout  = 10 * time.Second
	DefaultCloseInactiveTimeout = 10 * time.Minute
	DefaultCompressionBlockSize = 1024 * 1024 // 1MB
	DefaultAllowMissingInit     = true
)
