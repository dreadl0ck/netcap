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
	"encoding/json"
	"fmt"
	"go.uber.org/zap"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/davecgh/go-spew/spew"
	"github.com/gogo/protobuf/proto"
	"github.com/klauspost/pgzip"

	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/delimited"
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

// WriteCSV writes a CSV record.
func (w *jsonWriter) Write(msg proto.Message) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	_, err := w.jWriter.writeRecord(msg)

	return err
}

// WriteHeader writes a CSV header.
func (w *jsonWriter) WriteHeader(t types.Type) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	_, err := w.jWriter.writeHeader(NewHeader(t, w.wc.Source, w.wc.Version, w.wc.IncludesPayloads, w.wc.StartTime))

	return err
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

	spew.Dump(msg)
	panic("can not write as JSON")
}
