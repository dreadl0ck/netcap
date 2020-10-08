package core

import (
	"github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/types"
)

type DecoderAPI interface {
	// PostInit is called after the decoder has been initialized
	PostInit() error

	// DeInit is called prior to teardown
	DeInit() error

	// GetName returns the name of the decoder
	GetName() string

	// SetWriter sets the netcap writer to use for the decoder
	SetWriter(io.AuditRecordWriter)

	// GetType returns the netcap type of the decoder
	GetType() types.Type

	// GetDescription returns the description of the decoder
	GetDescription() string

	// GetChan returns a channel to receive serialized audit records from the decoder
	GetChan() <-chan []byte

	// Destroy initiates teardown
	Destroy() (string, int64)

	// NumRecords returns the number of processed audit records
	NumRecords() int64
}
