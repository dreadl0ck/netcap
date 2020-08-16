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
	"encoding/json"
	"fmt"
	"io"
	"sync"

	"github.com/davecgh/go-spew/spew"
	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/types"
)

// JSONProtoWriter implements writing audit records to disk in the JSON format.
type JSONProtoWriter struct {
	w io.Writer
	sync.Mutex
}

// NewJSONProtoWriter returns a new JSON writer instance.
func NewJSONProtoWriter(w io.Writer) *JSONProtoWriter {
	return &JSONProtoWriter{
		w: w,
	}
}

// WriteHeader writes the CSV header to the underlying file.
func (w *JSONProtoWriter) WriteHeader(h *types.Header) (int, error) {
	w.Lock()
	defer w.Unlock()

	marshaled, errMarshal := json.Marshal(h)
	if errMarshal != nil {
		return 0, fmt.Errorf("failed to marshal json: %w", errMarshal)
	}

	n, err := w.w.Write(marshaled)
	if err != nil {
		return n, err
	}

	return w.w.Write([]byte("\n"))
}

// WriteRecord writes a protocol buffer into the JSON writer.
func (w *JSONProtoWriter) WriteRecord(msg proto.Message) (int, error) {
	w.Lock()
	defer w.Unlock()

	if j, ok := msg.(types.AuditRecord); ok {
		js, err := j.JSON()
		if err != nil {
			return 0, err
		}

		return w.w.Write([]byte(js + "\n"))
	}

	spew.Dump(msg)
	panic("can not write as JSON")
}
