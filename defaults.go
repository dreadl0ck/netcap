package netcap

import "time"

const (
	DefaultBufferSize           = 1024 * 1024 // 1MB
	DefaultFlushEvery           = 100
	DefaultPacketBuffer         = 100
	DefaultSnapLen              = 1514
	DefaultConnFlushInterval    = 10000
	DefaultConnTimeOut          = 10 * time.Second
	DefaultFlowFlushInterval    = 2000
	DefaultFlowTimeOut          = 10 * time.Second
	DefaultClosePendingTimeout  = 5 * time.Second
	DefaultCloseInactiveTimeout = 24 * time.Hour
	DefaultCompressionBlockSize = 1024 * 1024 // 1MB
)
