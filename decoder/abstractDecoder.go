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

	netio "github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/types"
)

type (
	// AbstractDecoder implements custom logic to decode data from a TCP / UDP network conversation
	// this structure has an optimized field order to avoid excessive padding.
	AbstractDecoder struct {

		// Name of the decoder
		Name string

		// Description of the decoder
		Description string

		// Icon name for the decoder (for Maltego)
		Icon string

		// init functions
		PostInit func(decoder *AbstractDecoder) error
		DeInit   func(decoder *AbstractDecoder) error

		// used to keep track of the number of generated audit records
		NumRecordsWritten int64

		// Writer for audit records
		Writer netio.AuditRecordWriter

		// Type of the audit records produced by this decoder
		Type types.Type
	}
)

// CoreDecoderAPI interface implementation

// PostInitFunc is called after the decoder has been initialized.
func (sd *AbstractDecoder) PostInitFunc() error {
	if sd.PostInit == nil {
		return nil
	}

	return sd.PostInit(sd)
}

// DeInitFunc is called prior to teardown.
func (sd *AbstractDecoder) DeInitFunc() error {
	if sd.DeInit == nil {
		return nil
	}

	return sd.DeInit(sd)
}

// GetName returns the name of the
func (sd *AbstractDecoder) GetName() string {
	return sd.Name
}

// SetWriter sets the netcap writer to use for the
func (sd *AbstractDecoder) SetWriter(w netio.AuditRecordWriter) {
	sd.Writer = w
}

// GetType returns the netcap type of the
func (sd *AbstractDecoder) GetType() types.Type {
	return sd.Type
}

// GetDescription returns the description of the
func (sd *AbstractDecoder) GetDescription() string {
	return sd.Description
}

// Destroy closes and flushes all writers and calls deinit if set.
func (sd *AbstractDecoder) Destroy() (name string, size int64) {
	err := sd.DeInitFunc()
	if err != nil {
		panic(err)
	}

	return sd.Writer.Close(sd.NumRecordsWritten)
}

// GetChan returns a channel to receive serialized protobuf data from the encoder.
func (sd *AbstractDecoder) GetChan() <-chan []byte {
	if cw, ok := sd.Writer.(netio.ChannelAuditRecordWriter); ok {
		return cw.GetChan()
	}

	return nil
}

// NumRecords returns the number of written records.
func (sd *AbstractDecoder) NumRecords() int64 {
	return atomic.LoadInt64(&sd.NumRecordsWritten)
}
