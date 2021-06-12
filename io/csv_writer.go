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
	"github.com/gogo/protobuf/proto"
	"github.com/klauspost/pgzip"
	"go.uber.org/zap"
	"log"
	"os"
	"path/filepath"
	"runtime"

	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/types"
)

// csvWriter is a structure that supports writing CSV audit records to disk.
type csvWriter struct {
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

	_, err := w.csvWriter.writeRecord(msg)

	return err
}

// WriteHeader writes a CSV header.
func (w *csvWriter) WriteHeader(t types.Type) error {

	_, err := w.csvWriter.writeHeader(NewHeader(t, w.wc.Source, w.wc.Version, w.wc.IncludesPayloads, w.wc.StartTime), InitRecord(t))

	return err
}

// Close flushes and closes the writer and the associated file handles.
func (w *csvWriter) Close(numRecords int64) (name string, size int64) {

	if w.wc.Buffer {
		flushWriters(w.bWriter)
	}

	if w.wc.Compress {
		closeGzipWriters(w.gWriter)
	}

	return closeFile(w.wc.Out, w.file, w.wc.Name, numRecords)
}
