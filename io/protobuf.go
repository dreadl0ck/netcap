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
	"bufio"
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
	"github.com/dreadl0ck/netcap/delimited"
	"github.com/dreadl0ck/netcap/types"
)

// protoWriter is a structure that supports writing protobuf audit records to disk.
type protoWriter struct {
	mu sync.Mutex

	bWriter *bufio.Writer
	gWriter *pgzip.Writer
	dWriter *delimited.Writer
	pWriter *delimitedProtoWriter

	file   *os.File
	wc     *WriterConfig
	closed bool
}

// newProtoWriter initializes and configures a new protoWriter instance.
func newProtoWriter(wc *WriterConfig) *protoWriter {
	w := &protoWriter{}
	w.wc = wc

	if wc.MemBufferSize <= 0 {
		wc.MemBufferSize = defaults.BufferSize
	}

	if wc.Compress {
		w.file = createFile(filepath.Join(wc.Out, wc.Name), defaults.FileExtensionCompressed)
	} else {
		w.file = createFile(filepath.Join(wc.Out, wc.Name), defaults.FileExtension)
	}
	ioLog.Info("create protoWriter", zap.String("base", filepath.Join(wc.Out, wc.Name)), zap.String("type", wc.Type.String()))

	// buffer data?
	if wc.Buffer {
		if wc.Compress {
			// experiment: pgzip -> file
			var errGzipWriter error
			w.gWriter, errGzipWriter = pgzip.NewWriterLevel(w.file, wc.CompressionLevel)

			if errGzipWriter != nil {
				panic(errGzipWriter)
			}
			// experiment: buffer -> pgzip
			w.bWriter = bufio.NewWriterSize(w.gWriter, wc.MemBufferSize)
			// experiment: delimited -> buffer
			w.dWriter = delimited.NewWriter(w.bWriter)
		} else {
			w.bWriter = bufio.NewWriterSize(w.file, wc.MemBufferSize)
			w.dWriter = delimited.NewWriter(w.bWriter)
		}
	} else {
		if w.wc.Compress {
			var errGzipWriter error
			w.gWriter, errGzipWriter = pgzip.NewWriterLevel(w.file, wc.CompressionLevel)
			if errGzipWriter != nil {
				panic(errGzipWriter)
			}
			w.dWriter = delimited.NewWriter(w.gWriter)
		} else {
			w.dWriter = delimited.NewWriter(w.file)
		}
	}

	w.pWriter = newDelimitedProtoWriter(w.dWriter)

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

// WriteProto writes a protobuf message.
func (w *protoWriter) Write(msg proto.Message) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Check if writer has been closed
	if w.closed {
		return nil // Silently ignore writes to closed writer
	}

	// Track disk I/O performance
	if w.wc.PerfTracker != nil {
		start := time.Now()
		err := w.pWriter.putProto(msg)
		duration := time.Since(start)

		// Estimate bytes written (proto size + varint length)
		if err == nil {
			size := proto.Size(msg)
			w.wc.PerfTracker.RecordDiskWrite(w.wc.Name, duration, int64(size))
		}

		return err
	}

	return w.pWriter.putProto(msg)
}

// WriteHeader writes a netcap file header for protobuf encoded audit record files.
func (w *protoWriter) WriteHeader(t types.Type) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Check if writer has been closed
	if w.closed {
		return nil // Silently ignore writes to closed writer
	}

	return w.pWriter.putProto(NewHeader(t, w.wc.Source, w.wc.Version, w.wc.IncludesPayloads, w.wc.StartTime))
}

// Flush flushes any buffered data to disk without closing the writer.
// This is used during live capture to make audit records visible periodically.
func (w *protoWriter) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Check if writer has been closed
	if w.closed {
		return nil
	}

	// Flush the buffered writer
	if w.wc.Buffer && w.bWriter != nil {
		if err := w.bWriter.Flush(); err != nil {
			return err
		}
	}

	// For compressed streams, we need to flush the gzip writer too
	// Note: This writes a sync point but doesn't close the stream
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
func (w *protoWriter) Close(numRecords int64) (name string, size int64) {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Check if already closed
	if w.closed {
		return "", 0
	}

	// Mark as closed to prevent further writes
	w.closed = true

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
