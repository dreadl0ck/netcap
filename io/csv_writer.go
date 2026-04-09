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
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/klauspost/pgzip"
	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/types"
)

// csvWriter is a structure that supports writing CSV audit records to disk.
type csvWriter struct {
	mu sync.Mutex

	bWriter   *bufio.Writer
	gWriter   *pgzip.Writer
	csvWriter *csvProtoWriter

	file *os.File
	wc   *WriterConfig
}

// newCSVWriter initializes and configures a new protoWriter instance.
func newCSVWriter(wc *WriterConfig) *csvWriter {
	w := &csvWriter{}
	w.wc = wc

	if wc.MemBufferSize <= 0 {
		wc.MemBufferSize = defaults.BufferSize
	}

	// create file
	if wc.Compress {
		w.file = createFile(filepath.Join(wc.Out, w.wc.Name), ".csv.gz")
	} else {
		w.file = createFile(filepath.Join(wc.Out, w.wc.Name), ".csv")
	}
	ioLog.Info("create csvWriter", zap.String("base", filepath.Join(wc.Out, wc.Name)), zap.String("type", wc.Type.String()))

	if wc.Buffer {
		w.bWriter = bufio.NewWriterSize(w.file, wc.MemBufferSize)

		if wc.Compress {
			var errGzipWriter error
			w.gWriter, errGzipWriter = pgzip.NewWriterLevel(w.bWriter, wc.CompressionLevel)

			if errGzipWriter != nil {
				panic(errGzipWriter)
			}

			w.csvWriter = newCSVProtoWriter(w.gWriter, wc.Encode, wc.Label)
		} else {
			w.csvWriter = newCSVProtoWriter(w.bWriter, wc.Encode, wc.Label)
		}
	} else {
		if wc.Compress {
			var errGzipWriter error
			w.gWriter, errGzipWriter = pgzip.NewWriterLevel(w.file, wc.CompressionLevel)
			if errGzipWriter != nil {
				panic(errGzipWriter)
			}
			w.csvWriter = newCSVProtoWriter(w.gWriter, wc.Encode, wc.Label)
		} else {
			w.csvWriter = newCSVProtoWriter(w.file, wc.Encode, wc.Label)
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

// WriteCSV writes a CSV record.
func (w *csvWriter) Write(msg proto.Message) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Track disk I/O performance
	if w.wc.PerfTracker != nil {
		start := time.Now()
		n, err := w.csvWriter.writeRecord(msg)
		duration := time.Since(start)

		if err == nil && n > 0 {
			w.wc.PerfTracker.RecordDiskWrite(w.wc.Name, duration, int64(n))
		}

		return err
	}

	_, err := w.csvWriter.writeRecord(msg)

	return err
}

// WriteHeader writes a CSV header.
func (w *csvWriter) WriteHeader(t types.Type) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	_, err := w.csvWriter.writeHeader(NewHeader(t, w.wc.Source, w.wc.Version, w.wc.IncludesPayloads, w.wc.StartTime), InitRecord(t))

	return err
}

// Flush flushes any buffered data to disk without closing the writer.
// This is used during live capture to make audit records visible periodically.
func (w *csvWriter) Flush() error {
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
func (w *csvWriter) Close(numRecords int64) (name string, size int64) {
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
