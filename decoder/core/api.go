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

package core

import (
	"github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/types"
)

// DecoderAPI describes functionality of a decoder.
type DecoderAPI interface {

	// PostInitFunc is called after the decoder has been initialized
	PostInitFunc() error

	// DeInitFunc is called prior to teardown
	DeInitFunc() error

	// GetName returns the name of the decoder
	GetName() string

	// SetWriter sets the netcap writer to use for the decoder
	SetWriter(io.AuditRecordWriter)

	// GetWriter returns the current writer
	GetWriter() io.AuditRecordWriter

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

	// FlushCurrentState writes the current state of accumulating records to disk
	// without clearing the in-memory state. This is used during live capture
	// to periodically make data visible while continuing to track state.
	// Returns the number of records flushed.
	FlushCurrentState() int64
}
