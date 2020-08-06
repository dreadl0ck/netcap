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

package delimited

import (
	"bufio"
	"encoding/binary"
	"io"

	"github.com/gogo/protobuf/proto"
)

// Reader reads length-delimited records from a byte data source.
type Reader struct {
	data   []byte
	buffer *bufio.Reader
}

// NewReader returns a new delimited Reader for the records in r.
func NewReader(r io.Reader) *Reader {
	return &Reader{
		buffer: bufio.NewReader(r),
	}
}

// Next returns the next length-delimited record from the input
// Note:
//  - returns io.EOF if there are no more records available
//  - returns io.ErrUnexpectedEOF if a short record is found, with a length of n but fewer than n bytes of data
//  - since there is no resynchronization mechanism, it is generally not possible to recover from a short record in this format
//
// The slice returned is valid only until a subsequent call to Next.
func (r *Reader) Next() ([]byte, error) {
	// read size
	size, err := binary.ReadUvarint(r.buffer)
	if err != nil {
		return nil, err
	}

	// alloc memory for data
	if cap(r.data) < int(size) {
		r.data = make([]byte, size)
	} else {
		r.data = r.data[:size]
	}

	// read data from buffer
	if _, err = io.ReadFull(r.buffer, r.data); err != nil {
		return nil, err
	}

	return r.data, nil
}

// NextProto consumes the next available record by calling r.Next
// and decodes it into protobuf using proto.Unmarshal().
func (r *Reader) NextProto(pb proto.Message) error {
	// fetch next record
	rec, err := r.Next()
	if err != nil {
		return err
	}

	// unpack protocol buffer
	return proto.Unmarshal(rec, pb)
}
