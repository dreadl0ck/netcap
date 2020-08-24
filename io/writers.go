package io

import (
	"time"
)

// WriterConfig contains config parameters for a audit record writer.
type WriterConfig struct {

	// Writer Types:
	// Comma Separated Values writer
	CSV bool
	// Protobuf writer
	Proto bool
	// JSON writer
	JSON bool
	// Channel writer
	Chan bool
	// ChanSize is the size of chunks sent through the channel
	ChanSize int

	// Elastic db writer
	Elastic bool

	// ElasticConfig allows to overwrite elastic defaults
	ElasticConfig

	// The Null writer will write nothing to disk and discard all data.
	Null bool

	// Netcap header information
	Name          string
	Buffer        bool
	Compress      bool
	Out           string
	MemBufferSize int

	// Netcap header information
	Source           string
	Version          string
	IncludesPayloads bool
	StartTime        time.Time
}
