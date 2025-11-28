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
	"runtime"
	"sync"

	"go.uber.org/zap"

	"github.com/gogo/protobuf/proto"
	"github.com/klauspost/pgzip"

	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/delimited"
	"github.com/dreadl0ck/netcap/types"
)

// chanWriter writes length delimited, serialized protobuf records into a channel.
type chanWriter struct {
	mu sync.Mutex

	bWriter *bufio.Writer
	gWriter *pgzip.Writer
	dWriter *delimited.Writer
	cWriter *chanProtoWriter

	file *os.File
	wc   *WriterConfig
}

// newChanWriter initializes and configures a new chanWriter instance.
func newChanWriter(wc *WriterConfig) *chanWriter {
	w := &chanWriter{}
	w.wc = wc

	if wc.MemBufferSize <= 0 {
		wc.MemBufferSize = defaults.BufferSize
	}

	if wc.Buffer || wc.Compress {
		panic("buffering or compression cannot be activated when running using writeChan")
	}
	ioLog.Info("create chanWriter", zap.String("type", wc.Type.String()))

	w.cWriter = newChanProtoWriter(wc.ChanSize)

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
		if wc.Compress {
			var errGzipWriter error
			w.gWriter, errGzipWriter = pgzip.NewWriterLevel(w.file, wc.CompressionLevel)
			if errGzipWriter != nil {
				panic(errGzipWriter)
			}
			w.dWriter = delimited.NewWriter(w.gWriter)
		} else {
			// write into channel writer without compression
			w.dWriter = delimited.NewWriter(w.cWriter)
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

// WriteProto writes a protobuf message.
func (w *chanWriter) Write(msg proto.Message) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	data, err := proto.Marshal(msg)
	if err != nil {
		return err
	}

	_, err = w.cWriter.Write(data)

	return err
}

// WriteHeader writes a netcap file header for protobuf encoded audit record files.
func (w *chanWriter) WriteHeader(t types.Type) error {
	data, err := proto.Marshal(NewHeader(t, w.wc.Source, w.wc.Version, w.wc.IncludesPayloads, w.wc.StartTime))
	if err != nil {
		return err
	}

	_, err = w.cWriter.Write(data)

	return err
}

// Flush is a no-op for the channel writer since data is immediately sent to the channel.
func (w *chanWriter) Flush() error {
	return nil
}

// Close flushes and closes the writer and the associated file handles.
func (w *chanWriter) Close(numRecords int64) (name string, size int64) {
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

// GetChan returns a channel for receiving bytes.
func (w *chanWriter) GetChan() <-chan []byte {
	return w.cWriter.Chan()
}

// chanProtoWriter writes into a []byte chan.
type chanProtoWriter struct {
	ch chan []byte
}

// newChanProtoWriter returns a new channel proto writer instance.
func newChanProtoWriter(size int) *chanProtoWriter {
	return &chanProtoWriter{make(chan []byte, size)}
}

// Chan returns the byte channel used to receive data.
func (w *chanProtoWriter) Chan() <-chan []byte {
	return w.ch
}

// WriteRecord writes a protocol buffer into the channel writer.
func (w *chanProtoWriter) Write(p []byte) (int, error) {
	w.ch <- p

	return len(p), nil
}

// Close will close the channel writer.
func (w *chanProtoWriter) Close() error {
	close(w.ch)

	return nil
}
