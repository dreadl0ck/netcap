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

// Flush is a no-op for the null writer.
func (w *nullWriter) Flush() error {
	return nil
}

// Close flushes and closes the writer and the associated file handles.
func (w *nullWriter) Close(_ int64) (name string, size int64) {
	return "", 0
}
