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
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/davecgh/go-spew/spew"
	"github.com/gogo/protobuf/proto"
	"github.com/klauspost/pgzip"

	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/types"
)

// CSVWriter is a structure that supports writing CSV audit records to disk.
type CSVWriter struct {
	bWriter   *bufio.Writer
	gWriter   *pgzip.Writer
	csvWriter *CSVProtoWriter

	file *os.File
	mu   sync.Mutex
	wc   *WriterConfig
}

// NewCSVWriter initializes and configures a new ProtoWriter instance.
func NewCSVWriter(wc *WriterConfig) *CSVWriter {
	w := &CSVWriter{}
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

	if wc.Buffer {
		w.bWriter = bufio.NewWriterSize(w.file, wc.MemBufferSize)

		if wc.Compress {
			var errGzipWriter error
			w.gWriter, errGzipWriter = pgzip.NewWriterLevel(w.bWriter, defaults.CompressionLevel)

			if errGzipWriter != nil {
				panic(errGzipWriter)
			}

			w.csvWriter = NewCSVProtoWriter(w.gWriter)
		} else {
			w.csvWriter = NewCSVProtoWriter(w.bWriter)
		}
	} else {
		if wc.Compress {
			var errGzipWriter error
			w.gWriter, errGzipWriter = pgzip.NewWriterLevel(w.file, defaults.CompressionLevel)
			if errGzipWriter != nil {
				panic(errGzipWriter)
			}
			w.csvWriter = NewCSVProtoWriter(w.gWriter)
		} else {
			w.csvWriter = NewCSVProtoWriter(w.file)
		}
	}

	if w.gWriter != nil {
		// To get any performance gains, you should at least be compressing more than 1 megabyte of data at the time.
		// You should at least have a block size of 100k and at least a number of blocks that match the number of cores
		// your would like to utilize, but about twice the number of blocks would be the best.
		if err := w.gWriter.SetConcurrency(defaults.CompressionBlockSize, runtime.GOMAXPROCS(0)*2); err != nil {
			log.Fatal("failed to configure compression package: ", err)
		}
	}

	return w
}

// WriteCSV writes a CSV record.
func (w *CSVWriter) Write(msg proto.Message) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	_, err := w.csvWriter.WriteRecord(msg)

	return err
}

// WriteHeader writes a CSV header.
func (w *CSVWriter) WriteHeader(t types.Type) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	_, err := w.csvWriter.WriteHeader(NewHeader(t, w.wc.Source, w.wc.Version, w.wc.IncludesPayloads, w.wc.StartTime), InitRecord(t))

	return err
}

// Close flushes and closes the writer and the associated file handles.
func (w *CSVWriter) Close() (name string, size int64) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.wc.Buffer {
		flushWriters(w.bWriter)
	}

	if w.wc.Compress {
		closeGzipWriters(w.gWriter)
	}

	return closeFile(w.wc.Out, w.file, w.wc.Name)
}

// CSVProtoWriter implements writing audit records to disk in the CSV format.
type CSVProtoWriter struct {
	w io.Writer
	sync.Mutex
}

// NewCSVProtoWriter returns a new CSV writer instance.
func NewCSVProtoWriter(w io.Writer) *CSVProtoWriter {
	return &CSVProtoWriter{
		w: w,
	}
}

// WriteHeader writes the CSV header to the underlying file.
func (w *CSVProtoWriter) WriteHeader(h *types.Header, msg proto.Message) (int, error) {
	w.Lock()
	defer w.Unlock()

	n, err := w.w.Write([]byte(fmt.Sprintf("# Type: %s, Created: %s, Source: %s, ContainsPayloads: %t\n", h.Type.String(), h.Created, h.InputSource, h.ContainsPayloads)))
	if err != nil {
		return n, err
	}

	if csv, ok := msg.(types.AuditRecord); ok {
		return w.w.Write([]byte(strings.Join(csv.CSVHeader(), ",") + "\n"))
	}

	spew.Dump(msg)
	panic("protocol buffer does not implement the types.AuditRecord interface")
}

// WriteRecord writes a protocol buffer into the CSV writer.
func (w *CSVProtoWriter) WriteRecord(msg proto.Message) (int, error) {
	w.Lock()
	defer w.Unlock()

	if csv, ok := msg.(types.AuditRecord); ok {
		return w.w.Write([]byte(strings.Join(csv.CSVRecord(), ",") + "\n"))
	}

	spew.Dump(msg)
	panic("can not write as CSV")
}
