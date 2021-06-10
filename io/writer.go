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

package io

import (
	"github.com/davecgh/go-spew/spew"
	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/types"
)

// AuditRecordWriter is an interface for writing netcap audit records.
type AuditRecordWriter interface {
	Write(msg proto.Message) error
	WriteHeader(t types.Type) error
	Close(numRecords int64) (name string, size int64)
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
		spew.Dump(wc)
		panic("invalid WriterConfig")
	}

	return nil //nolint:govet // stop complaining that this is unreachable
}
