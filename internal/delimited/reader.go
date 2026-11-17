/*
 * NETCAP - Network Capture Framework
 * Copyright (c) 2017-2025 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
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
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"math"

	"github.com/gogo/protobuf/proto"
)

// Reader reads length-delimited records from a byte data source.
type Reader struct {
	data      []byte
	buffer    *bufio.Reader
	maxRecord uint64
}

// NewReaderWithLimit rejects oversized frames before allocating their payload.
func NewReaderWithLimit(r io.Reader, maxRecord uint64) *Reader {
	return &Reader{buffer: bufio.NewReader(r), maxRecord: maxRecord}
}

// NewReader returns a new delimited Reader for the records in r.
func NewReader(r io.Reader) *Reader {
	return &Reader{
		buffer: bufio.NewReader(r),
	}
}

// Next returns the next length-delimited record from the input
// Note:
//   - returns io.EOF if there are no more records available
//   - returns io.ErrUnexpectedEOF if a short record is found, with a length of n but fewer than n bytes of data
//   - since there is no resynchronization mechanism, it is generally not possible to recover from a short record in this format
//
// The slice returned is valid only until a subsequent call to Next.
func (r *Reader) Next() ([]byte, error) {
	return r.next(r.maxRecord)
}

func (r *Reader) next(limit uint64) ([]byte, error) {
	// read size
	size, err := binary.ReadUvarint(r.buffer)
	if err != nil {
		return nil, err
	}
	if limit > 0 && size > limit {
		return nil, fmt.Errorf("record size %d exceeds limit %d", size, limit)
	}
	if size > math.MaxInt {
		return nil, fmt.Errorf("record size %d exceeds reader bounds", size)
	}

	r.data = r.data[:0]
	for len(r.data) < int(size) {
		if len(r.data) == cap(r.data) {
			// Do not allocate from a declared length without seeing body bytes.
			if _, err = r.buffer.Peek(1); err != nil {
				if err == io.EOF {
					err = io.ErrUnexpectedEOF
				}
				return nil, err
			}
			growth := min(int(size)-len(r.data), max(4096, cap(r.data)))
			grown := make([]byte, len(r.data), len(r.data)+growth)
			copy(grown, r.data)
			r.data = grown
		}
		end := min(int(size), cap(r.data))
		if _, err = io.ReadFull(r.buffer, r.data[len(r.data):end]); err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return nil, err
		}
		r.data = r.data[:end]
	}

	return r.data, nil
}

// Skip consumes one frame without allocating its body.
func (r *Reader) Skip(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	size, err := binary.ReadUvarint(r.buffer)
	if err != nil {
		return err
	}
	if r.maxRecord > 0 && size > r.maxRecord {
		return fmt.Errorf("record size %d exceeds limit %d", size, r.maxRecord)
	}
	for size > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := r.buffer.Discard(int(min(size, 32<<10)))
		size -= uint64(n)
		if err == io.EOF {
			return io.ErrUnexpectedEOF
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// NextProtoWithLimit applies an additional allocation limit to one frame.
func (r *Reader) NextProtoWithLimit(pb proto.Message, limit uint64) error {
	if r.maxRecord > 0 && (limit == 0 || r.maxRecord < limit) {
		limit = r.maxRecord
	}
	record, err := r.next(limit)
	if err != nil {
		return err
	}
	return proto.Unmarshal(record, pb)
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
