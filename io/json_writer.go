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
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/gogo/protobuf/proto"
	"github.com/klauspost/pgzip"

	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/internal/delimited"
	"github.com/dreadl0ck/netcap/types"
)

// jsonWriter is a structure that supports writing JSON audit records to disk.
type jsonWriter struct {
	mu      sync.Mutex
	bWriter *bufio.Writer
	gWriter *pgzip.Writer
	dWriter *delimited.Writer
	jWriter *jsonProtoWriter

	file *os.File
	wc   *WriterConfig
}

// newJSONWriter initializes and configures a new jsonWriter instance.
func newJSONWriter(wc *WriterConfig) *jsonWriter {
	w := &jsonWriter{}
	w.wc = wc

	if wc.MemBufferSize <= 0 {
		wc.MemBufferSize = defaults.BufferSize
	}

	// create file
	if wc.Compress {
		w.file = createFile(filepath.Join(wc.Out, w.wc.Name), ".json.gz")
	} else {
		w.file = createFile(filepath.Join(wc.Out, w.wc.Name), ".json")
	}
	ioLog.Info("create jsonWriter", zap.String("base", filepath.Join(wc.Out, wc.Name)), zap.String("type", wc.Type.String()))

	if wc.Buffer {
		w.bWriter = bufio.NewWriterSize(w.file, wc.MemBufferSize)

		if wc.Compress {
			var errGzipWriter error
			w.gWriter, errGzipWriter = pgzip.NewWriterLevel(w.bWriter, wc.CompressionLevel)

			if errGzipWriter != nil {
				panic(errGzipWriter)
			}

			w.jWriter = newJSONProtoWriter(w.gWriter)
		} else {
			w.jWriter = newJSONProtoWriter(w.bWriter)
		}
	} else {
		if wc.Compress {
			var errGzipWriter error
			w.gWriter, errGzipWriter = pgzip.NewWriterLevel(w.file, wc.CompressionLevel)
			if errGzipWriter != nil {
				panic(errGzipWriter)
			}
			w.jWriter = newJSONProtoWriter(w.gWriter)
		} else {
			w.jWriter = newJSONProtoWriter(w.file)
		}
	}

	if w.gWriter != nil {
		// To get any performance gains, you should at least be compressing more than 1 megabyte of data at the time.
		// You should at least have a block size of 100k and at least a number of blocks that match the number of cores
		// you would like to utilize, but about twice the number of blocks would be the best.
		if err := w.gWriter.SetConcurrency(wc.CompressionBlockSize, runtime.GOMAXPROCS(0)*2); err != nil {
			log.Fatal("failed to configure compression package: ", err)
		}
	}

	return w
}

// Write writes a JSON record.
// The inner jsonProtoWriter handles its own locking for the actual write,
// so we don't hold the outer lock during JSON marshaling.
func (w *jsonWriter) Write(msg proto.Message) error {
	// Track disk I/O performance
	if w.wc.PerfTracker != nil {
		start := time.Now()
		n, err := w.jWriter.writeRecord(msg)
		duration := time.Since(start)

		if err == nil && n > 0 {
			w.wc.PerfTracker.RecordDiskWrite(w.wc.Name, duration, int64(n))
		}

		return err
	}

	_, err := w.jWriter.writeRecord(msg)

	return err
}

// WriteHeader writes a JSON header.
func (w *jsonWriter) WriteHeader(t types.Type) error {
	_, err := w.jWriter.writeHeader(NewHeader(t, w.wc.Source, w.wc.Version, w.wc.IncludesPayloads, w.wc.StartTime))

	return err
}

// Flush flushes any buffered data to disk without closing the writer.
// This is used during live capture to make audit records visible periodically.
func (w *jsonWriter) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Flush the buffered writer
	if w.wc.Buffer && w.bWriter != nil {
		if err := w.bWriter.Flush(); err != nil {
			return err
		}
	}

	// For compressed streams, flush the gzip writer
	if w.wc.Compress && w.gWriter != nil {
		if err := w.gWriter.Flush(); err != nil {
			return err
		}
	}

	// Sync file to disk
	if w.file != nil {
		if err := w.file.Sync(); err != nil {
			return err
		}
	}

	return nil
}

// Close flushes and closes the writer and the associated file handles.
func (w *jsonWriter) Close(numRecords int64) (name string, size int64) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.wc.Buffer {
		flushWriters(w.bWriter)
	}

	if w.wc.Compress {
		closeGzipWriters(w.gWriter)
	}

	// Track file sync performance
	if w.wc.PerfTracker != nil && w.file != nil {
		start := time.Now()
		_ = w.file.Sync()
		w.wc.PerfTracker.RecordDiskSync(w.wc.Name, time.Since(start))
	}

	return closeFile(w.wc.Out, w.file, w.wc.Name, numRecords)
}

// jsonProtoWriter implements writing audit records to disk in the JSON format.
type jsonProtoWriter struct {
	sync.Mutex
	w io.Writer
}

// newJSONProtoWriter returns a new JSON writer instance.
func newJSONProtoWriter(w io.Writer) *jsonProtoWriter {
	return &jsonProtoWriter{
		w: w,
	}
}

// writeHeader writes the CSV header to the underlying file.
func (w *jsonProtoWriter) writeHeader(h *types.Header) (int, error) {
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

// writeRecord writes a protocol buffer into the JSON writer.
func (w *jsonProtoWriter) writeRecord(msg proto.Message) (int, error) {

	if j, ok := msg.(types.AuditRecord); ok {
		js, err := j.JSON()
		if err != nil {
			return 0, err
		}

		out := []byte(js + "\n")

		w.Lock()
		n, err := w.w.Write(out)
		w.Unlock()

		return n, err
	}

	return 0, fmt.Errorf("%w (writeRecord as JSON, type %T)", errNotAuditRecord, msg)
}
