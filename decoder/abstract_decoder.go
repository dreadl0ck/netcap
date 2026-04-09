/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
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

// GetWriter returns the current writer.
func (ad *AbstractDecoder) GetWriter() netio.AuditRecordWriter {
	return ad.Writer
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

// FlushCurrentState flushes the writer buffer for abstract decoders.
// Abstract decoders write records immediately, so there's no accumulated state to flush.
// This just ensures any buffered data is written to disk.
func (ad *AbstractDecoder) FlushCurrentState() int64 {
	if ad.Writer != nil {
		_ = ad.Writer.Flush()
	}
	return 0
}
