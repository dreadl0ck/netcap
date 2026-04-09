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

package io

import (
	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/types"
)

// AuditRecordWriter is an interface for writing netcap audit records.
type AuditRecordWriter interface {
	Write(msg proto.Message) error
	WriteHeader(t types.Type) error
	Close(numRecords int64) (name string, size int64)
	// Flush flushes any buffered data to disk without closing the writer.
	// This is used during live capture to make audit records visible periodically.
	Flush() error
}

// ChannelAuditRecordWriter extends the AuditRecordWriter
// by offering a function to get a channel to receive serialized audit records.
type ChannelAuditRecordWriter interface {
	AuditRecordWriter
	GetChan() <-chan []byte
}

// NewAuditRecordWriter will return a new writer for netcap audit records.
func NewAuditRecordWriter(wc *WriterConfig) AuditRecordWriter {
	switch {
	case wc.UnixSocket:
		return newUnixSocketWriter(wc)
	case wc.CSV:
		return newCSVWriter(wc)
	case wc.Chan:
		return newChanWriter(wc)
	case wc.JSON:
		return newJSONWriter(wc)
	case wc.Null:
		return newNullWriter(wc)
	case wc.Elastic:
		return newElasticWriter(wc)

	// proto is the default, so this option should be checked last to allow overwriting it
	case wc.Proto:
		return newProtoWriter(wc)
	default:
		// Default to proto when no writer type is specified
		return newProtoWriter(wc)
	}

	return nil //nolint:govet // stop complaining that this is unreachable
}
