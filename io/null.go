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
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
	"go.uber.org/zap"
)

// nullWriter is a writer that writes nothing to disk.
type nullWriter struct{}

// newNullWriter initializes and configures a new nullWriter instance.
func newNullWriter(wc *WriterConfig) *nullWriter {
	ioLog.Info("create nullWriter", zap.String("type", wc.Type.String()))
	return &nullWriter{}
}

// WriteCSV writes a CSV record.
func (w *nullWriter) Write(_ proto.Message) error {
	return nil
}

// WriteHeader writes a CSV header.
func (w *nullWriter) WriteHeader(_ types.Type) error {
	return nil
}

// Close flushes and closes the writer and the associated file handles.
func (w *nullWriter) Close(_ int64) (name string, size int64) {
	return "", 0
}
