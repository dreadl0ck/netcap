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

		// used to keep track of the number of generated audit records
		NumRecordsWritten int64

		// Name of the decoder
		Name string

		// Description of the decoder
		Description string

		// Icon name for the decoder (for Maltego)
		Icon string

		// init functions
		PostInit func(decoder *AbstractDecoder) error
		DeInit   func(decoder *AbstractDecoder) error

		// Writer for audit records
		Writer netio.AuditRecordWriter

		// Type of the audit records produced by this decoder
		Type types.Type
	}
)

// CoreDecoderAPI interface implementation

// PostInitFunc is called after the decoder has been initialized.
func (ad *AbstractDecoder) PostInitFunc() error {
	if ad.PostInit == nil {
		return nil
	}

	return ad.PostInit(ad)
}

// DeInitFunc is called prior to teardown.
func (ad *AbstractDecoder) DeInitFunc() error {
	if ad.DeInit == nil {
		return nil
	}

	return ad.DeInit(ad)
}

// GetName returns the name of the
func (ad *AbstractDecoder) GetName() string {
	return ad.Name
}

// SetWriter sets the netcap writer to use for the
func (ad *AbstractDecoder) SetWriter(w netio.AuditRecordWriter) {
	ad.Writer = w
}

// GetType returns the netcap type of the
func (ad *AbstractDecoder) GetType() types.Type {
	return ad.Type
}

// GetDescription returns the description of the
func (ad *AbstractDecoder) GetDescription() string {
	return ad.Description
}

// Destroy closes and flushes all writers and calls deinit if set.
func (ad *AbstractDecoder) Destroy() (name string, size int64) {
	err := ad.DeInitFunc()
	if err != nil {
		panic(err)
	}

	return ad.Writer.Close(ad.NumRecordsWritten)
}

// GetChan returns a channel to receive serialized protobuf data from the decoder.
func (ad *AbstractDecoder) GetChan() <-chan []byte {
	if cw, ok := ad.Writer.(netio.ChannelAuditRecordWriter); ok {
		return cw.GetChan()
	}

	return nil
}

// NumRecords returns the number of written records.
func (ad *AbstractDecoder) NumRecords() int64 {
	return atomic.LoadInt64(&ad.NumRecordsWritten)
}
