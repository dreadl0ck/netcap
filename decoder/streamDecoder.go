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

package decoder

import (
	"sync/atomic"

	"github.com/dreadl0ck/netcap/decoder/core"

	netio "github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/types"
)

type (
	// StreamDecoder implements custom logic to decode data from a TCP / UDP network conversation
	// this structure has an optimized field order to avoid excessive padding.
	StreamDecoder struct {

		// used to keep track of the number of generated audit records
		NumRecordsWritten int64

		// Name of the decoder
		Name string

		// Description of the decoder
		Description string

		// Icon name for the decoder (for Maltego)
		Icon string

		// init functions
		PostInit func(decoder *StreamDecoder) error
		DeInit   func(decoder *StreamDecoder) error

		// Writer for audit records
		Writer netio.AuditRecordWriter

		// Type of the audit records produced by this decoder
		Type types.Type

		// canDecode checks whether the decoder can parse the protocol
		CanDecode func(client []byte, server []byte) bool

		// factory for stream readers
		Factory core.StreamDecoderFactory

		Typ core.TransportProtocol
	}
)

// StreamDecoderAPI interface implementation

// GetReaderFactory returns a new stream reader for the decoder type.
func (sd *StreamDecoder) GetReaderFactory() core.StreamDecoderFactory {
	return sd.Factory
}

// PostInitFunc is called after the decoder has been initialized.
func (sd *StreamDecoder) PostInitFunc() error {
	if sd.PostInit == nil {
		return nil
	}

	return sd.PostInit(sd)
}

// DeInitFunc is called prior to teardown.
func (sd *StreamDecoder) DeInitFunc() error {
	if sd.DeInit == nil {
		return nil
	}

	return sd.DeInit(sd)
}

// GetName returns the name of the
func (sd *StreamDecoder) GetName() string {
	return sd.Name
}

// SetWriter sets the netcap writer to use for the
func (sd *StreamDecoder) SetWriter(w netio.AuditRecordWriter) {
	sd.Writer = w
}

// GetType returns the netcap type of the
func (sd *StreamDecoder) GetType() types.Type {
	return sd.Type
}

// GetDescription returns the description of the
func (sd *StreamDecoder) GetDescription() string {
	return sd.Description
}

// Destroy closes and flushes all writers and calls deinit if set.
func (sd *StreamDecoder) Destroy() (name string, size int64) {
	err := sd.DeInitFunc()
	if err != nil {
		panic(err)
	}

	return sd.Writer.Close(sd.NumRecordsWritten)
}

// GetChan returns a channel to receive serialized protobuf data from the decoder.
func (sd *StreamDecoder) GetChan() <-chan []byte {
	if cw, ok := sd.Writer.(netio.ChannelAuditRecordWriter); ok {
		return cw.GetChan()
	}

	return nil
}

// NumRecords returns the number of written records.
func (sd *StreamDecoder) NumRecords() int64 {
	return atomic.LoadInt64(&sd.NumRecordsWritten)
}

// CanDecodeStream invokes the canDecode function of the underlying decoder
// to determine whether the decoder can understand the protocol.
func (sd *StreamDecoder) CanDecodeStream(client []byte, server []byte) bool {
	return sd.CanDecode(client, server)
}

// Transport returns the transport protocol (Layer 4 in the OSI model)
func (sd *StreamDecoder) Transport() core.TransportProtocol {
	return sd.Typ
}
