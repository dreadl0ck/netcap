/*
 * NETCAP - Network Capture Framework
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

// Package delimited implements a simple reader and writer for streams of length-delimited byte records.
// Each record is written as a varint-encoded length in bytes, followed immediately by the record itself.
// A stream consists of a sequence of such records packed consecutively without additional padding.
// No checksums or compression are being used.
package delimited

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/gogo/protobuf/proto"
)

// Writer outputs delimited records to an io.Writer.
type Writer struct {
	w io.Writer
}

// NewWriter constructs a new delimited Writer that writes records to w.
func NewWriter(w io.Writer) *Writer {
	return &Writer{w: w}
}

// Put writes the specified record to the writer
// Note:
//  - equivalent to writeRecord, but discards the number of bytes written
func (w Writer) Put(record []byte) error {
	// ignore the amount of bytes written
	_, err := w.writeRecord(record)

	return err
}

// PutProto encodes and writes the specified proto.Message to the writer.
func (w Writer) PutProto(msg proto.Message) error {
	// pack protocol buffer
	rec, err := proto.Marshal(msg)
	if err != nil {
		return fmt.Errorf("error encoding proto: %w", err)
	}

	// write record and return error
	return w.Put(rec)
}

// writeRecord writes the specified record to the underlying writer
// Note:
//  - returns the total number of bytes written including the length tag
func (w Writer) writeRecord(record []byte) (int, error) {
	var (
		buffer [binary.MaxVarintLen64]byte
		varint = binary.PutUvarint(buffer[:], uint64(len(record)))
	)

	// write length
	lengthWritten, err := w.w.Write(buffer[:varint])
	if err != nil {
		return 0, err
	}

	// write data
	dataWritten, err := w.w.Write(record)
	if err != nil {
		return lengthWritten, err
	}

	return lengthWritten + dataWritten, nil
}
