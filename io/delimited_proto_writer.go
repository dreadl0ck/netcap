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

// Package io implements IO primitives
package io

import (
	"fmt"
	"sync"

	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/internal/delimited"
)

/*
 * Atomic Delimited Writer
 * A primitive for a concurrency safe writer for length delimited binary data
 */

// delimitedProtoWriter writes length delimited protobuf messages synchronized.
type delimitedProtoWriter struct {
	sync.Mutex
	w      delimited.Writer
	buffer []byte
}

const maxProtoBufferSize = 1 << 20

// putProto returns the encoded message size, excluding the length prefix.
func (a *delimitedProtoWriter) putProto(pb proto.Message) (int, error) {
	a.Lock()
	defer a.Unlock()

	var record []byte
	var err error
	if msg, ok := pb.(interface {
		Size() int
		MarshalToSizedBuffer([]byte) (int, error)
	}); ok {
		size := msg.Size()
		buffer := a.buffer
		if cap(buffer) < size {
			buffer = make([]byte, size)
			if size <= maxProtoBufferSize {
				a.buffer = buffer
			}
		}
		// Generated marshalers write backwards from the end of the slice.
		record = buffer[:size]
		var n int
		n, err = msg.MarshalToSizedBuffer(record)
		if err == nil {
			record = record[size-n:]
		}
	} else {
		// Preserve support for messages without generated sized-buffer marshaling.
		record, err = proto.Marshal(pb)
	}
	if err != nil {
		return 0, fmt.Errorf("error encoding proto: %w", err)
	}

	return len(record), a.w.Put(record)
}

// newDelimitedProtoWriter takes a delimited.WriterAtomic and returns an atomic version.
func newDelimitedProtoWriter(w *delimited.Writer) *delimitedProtoWriter {
	return &delimitedProtoWriter{
		w: *w,
	}
}
