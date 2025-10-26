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

package webui

import (
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"strings"

	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/delimited"
	netio "github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/types"
)

// AuditRecordReader reads audit records from .ncap files
type AuditRecordReader struct {
	file            *os.File
	reader          io.Reader
	gzReader        *gzip.Reader
	delimitedReader *delimited.Reader
	recordType      types.Type
}

// NewAuditRecordReader creates a new audit record reader
func NewAuditRecordReader(filePath string) (*AuditRecordReader, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}

	var reader io.Reader = file
	var gzReader *gzip.Reader

	// Check if file is gzipped
	if strings.HasSuffix(filePath, ".gz") {
		gzReader, err = gzip.NewReader(file)
		if err != nil {
			file.Close()
			return nil, err
		}
		reader = gzReader
	}

	return &AuditRecordReader{
		file:            file,
		reader:          reader,
		gzReader:        gzReader,
		delimitedReader: delimited.NewReader(reader),
	}, nil
}

// ReadHeader reads the audit record file header
func (r *AuditRecordReader) ReadHeader() (*types.Header, error) {
	header := &types.Header{}
	err := r.delimitedReader.NextProto(header)
	if err != nil {
		return nil, err
	}
	r.recordType = header.Type
	return header, nil
}

// NextRecord reads the next audit record as a proto.Message
// The caller needs to type assert to the appropriate type
func (r *AuditRecordReader) NextRecord() (proto.Message, error) {
	// Create appropriate message type based on header
	msg := netio.InitRecord(r.recordType)
	if msg == nil {
		// If header not read yet or unknown type, return a placeholder
		return &types.Connection{}, io.EOF
	}

	err := r.delimitedReader.NextProto(msg)
	if err != nil {
		return nil, err
	}

	return msg, nil
}

// NextAsJSON reads the next audit record and returns it as JSON
func (r *AuditRecordReader) NextAsJSON() (string, error) {
	msg, err := r.NextRecord()
	if err != nil {
		return "", err
	}

	// Convert proto message to JSON
	data, err := json.Marshal(msg)
	if err != nil {
		return "", err
	}

	return string(data), nil
}

// Skip skips n records from the current position
func (r *AuditRecordReader) Skip(n int) error {
	for i := 0; i < n; i++ {
		_, err := r.delimitedReader.Next()
		if err != nil {
			return err
		}
	}
	return nil
}

// Close closes the reader and underlying file
func (r *AuditRecordReader) Close() error {
	if r.gzReader != nil {
		r.gzReader.Close()
	}
	if r.file != nil {
		return r.file.Close()
	}
	return nil
}
