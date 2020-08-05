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
	"io"
	"strings"
	"sync"

	"github.com/davecgh/go-spew/spew"
	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/types"
)

// CSVWriter implements writing audit records to disk in the CSV format.
type CSVWriter struct {
	w io.Writer
	sync.Mutex
}

// NewCSVWriter returns a new CSV writer instance.
func NewCSVWriter(w io.Writer) *CSVWriter {
	return &CSVWriter{
		w: w,
	}
}

// WriteHeader writes the CSV header to the underlying file.
func (w *CSVWriter) WriteHeader(msg proto.Message) (int, error) {
	w.Lock()
	defer w.Unlock()

	if csv, ok := msg.(types.AuditRecord); ok {
		return w.w.Write([]byte(strings.Join(csv.CSVHeader(), ",") + "\n"))
	}

	spew.Dump(msg)
	panic("protocol buffer does not implement the types.AuditRecord interface")
}

// WriteRecord writes a protocol buffer into the CSV writer.
func (w *CSVWriter) WriteRecord(msg proto.Message) (int, error) {
	w.Lock()
	defer w.Unlock()

	if csv, ok := msg.(types.AuditRecord); ok {
		return w.w.Write([]byte(strings.Join(csv.CSVRecord(), ",") + "\n"))
	}

	spew.Dump(msg)
	panic("can not write as CSV")
}
