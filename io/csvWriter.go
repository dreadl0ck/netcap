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
	"github.com/dreadl0ck/netcap/utils"
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

// newCSVWriter initializes and configures a new protoWriter instance.
func newCSVWriter(wc *WriterConfig) *CSVWriter {
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
			w.gWriter, errGzipWriter = pgzip.NewWriterLevel(w.bWriter, wc.CompressionLevel)

			if errGzipWriter != nil {
				panic(errGzipWriter)
			}

			w.csvWriter = newCSVProtoWriter(w.gWriter)
		} else {
			w.csvWriter = newCSVProtoWriter(w.bWriter)
		}
	} else {
		if wc.Compress {
			var errGzipWriter error
			w.gWriter, errGzipWriter = pgzip.NewWriterLevel(w.file, wc.CompressionLevel)
			if errGzipWriter != nil {
				panic(errGzipWriter)
			}
			w.csvWriter = newCSVProtoWriter(w.gWriter)
		} else {
			w.csvWriter = newCSVProtoWriter(w.file)
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
func (w *CSVWriter) Write(msg proto.Message) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	_, err := w.csvWriter.writeRecord(msg)

	return err
}

// WriteHeader writes a CSV header.
func (w *CSVWriter) WriteHeader(t types.Type) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	_, err := w.csvWriter.writeHeader(NewHeader(t, w.wc.Source, w.wc.Version, w.wc.IncludesPayloads, w.wc.StartTime), InitRecord(t))

	return err
}

// Close flushes and closes the writer and the associated file handles.
func (w *CSVWriter) Close(numRecords int64) (name string, size int64) {
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

// CSVProtoWriter implements writing audit records to disk in the CSV format.
type CSVProtoWriter struct {
	w io.Writer
	sync.Mutex
}

// newCSVProtoWriter returns a new CSV writer instance.
func newCSVProtoWriter(w io.Writer) *CSVProtoWriter {
	return &CSVProtoWriter{
		w: w,
	}
}

// writeHeader writes the CSV header to the underlying file.
func (w *CSVProtoWriter) writeHeader(h *types.Header, msg proto.Message) (int, error) {
	w.Lock()
	defer w.Unlock()

	n, err := w.w.Write([]byte(fmt.Sprintf("# Type: %s, Created: %s, Source: %s, ContainsPayloads: %t\n", h.Type.String(), utils.UnixTimeToUTC(h.Created), h.InputSource, h.ContainsPayloads)))
	if err != nil {
		return n, err
	}

	if csv, ok := msg.(types.AuditRecord); ok {
		return w.w.Write([]byte(strings.Join(csv.CSVHeader(), ",") + "\n"))
	}

	spew.Dump(msg)
	panic("protocol buffer does not implement the types.AuditRecord interface")
}

// writeRecord writes a protocol buffer into the CSV writer.
func (w *CSVProtoWriter) writeRecord(msg proto.Message) (int, error) {
	w.Lock()
	defer w.Unlock()

	if csv, ok := msg.(types.AuditRecord); ok {
		return w.w.Write([]byte(strings.Join(csv.CSVRecord(), ",") + "\n"))
	}

	spew.Dump(msg)
	panic("can not write as CSV")
}
