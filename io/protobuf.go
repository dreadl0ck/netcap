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
	"go.uber.org/zap"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sync"

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

	file *os.File
	wc   *WriterConfig
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

	return w.pWriter.putProto(msg)
}

// WriteHeader writes a netcap file header for protobuf encoded audit record files.
func (w *protoWriter) WriteHeader(t types.Type) error {
	return w.pWriter.putProto(NewHeader(t, w.wc.Source, w.wc.Version, w.wc.IncludesPayloads, w.wc.StartTime))
}

// Close flushes and closes the writer and the associated file handles.
func (w *protoWriter) Close(numRecords int64) (name string, size int64) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.wc.Buffer {
		flushWriters(w.bWriter)
	}

	if w.wc.Compress {
		closeGzipWriters(w.gWriter)
	}

	return closeFile(w.wc.Out, w.file, w.wc.Name, numRecords)
}
