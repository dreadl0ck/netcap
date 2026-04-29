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
	"net"
	"path/filepath"
	"runtime"

	"go.uber.org/zap"

	"github.com/gogo/protobuf/proto"
	"github.com/klauspost/pgzip"

	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/types"
)

// unixSocketWriter is a structure that supports writing CSV audit records to disk.
type unixSocketWriter struct {
	bWriter          *bufio.Writer
	gWriter          *pgzip.Writer
	unixSocketWriter *csvProtoWriter

	conn *net.UnixConn

	wc *WriterConfig
}

// newCSVWriter initializes and configures a new protoWriter instance.
func newUnixSocketWriter(wc *WriterConfig) *unixSocketWriter {
	w := &unixSocketWriter{}
	w.wc = wc

	if wc.MemBufferSize <= 0 {
		wc.MemBufferSize = defaults.BufferSize
	}

	// create socket
	w.conn = createUnixSocket(filepath.Join(wc.Out, w.wc.Name))
	ioLog.Info("create unixSocketWriter", zap.String("base", filepath.Join(wc.Out, wc.Name)), zap.String("type", wc.Type.String()))

	if wc.Buffer {
		w.bWriter = bufio.NewWriterSize(w.conn, wc.MemBufferSize)

		if wc.Compress {
			var errGzipWriter error
			w.gWriter, errGzipWriter = pgzip.NewWriterLevel(w.bWriter, wc.CompressionLevel)

			if errGzipWriter != nil {
				panic(errGzipWriter)
			}

			w.unixSocketWriter = newCSVProtoWriter(w.gWriter, wc.Encode, wc.Label, wc.LabelManager)
		} else {
			w.unixSocketWriter = newCSVProtoWriter(w.bWriter, wc.Encode, wc.Label, wc.LabelManager)
		}
	} else {
		if wc.Compress {
			var errGzipWriter error
			w.gWriter, errGzipWriter = pgzip.NewWriterLevel(w.conn, wc.CompressionLevel)
			if errGzipWriter != nil {
				panic(errGzipWriter)
			}
			w.unixSocketWriter = newCSVProtoWriter(w.gWriter, wc.Encode, wc.Label, wc.LabelManager)
		} else {
			w.unixSocketWriter = newCSVProtoWriter(w.conn, wc.Encode, wc.Label, wc.LabelManager)
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
func (w *unixSocketWriter) Write(msg proto.Message) error {

	_, err := w.unixSocketWriter.writeRecord(msg)

	return err
}

// WriteHeader writes a CSV header.
func (w *unixSocketWriter) WriteHeader(t types.Type) error {

	_, err := w.unixSocketWriter.writeHeader(NewHeader(t, w.wc.Source, w.wc.Version, w.wc.IncludesPayloads, w.wc.StartTime), InitRecord(t))

	return err
}

// Flush flushes any buffered data to the socket.
func (w *unixSocketWriter) Flush() error {
	if w.wc.Buffer && w.bWriter != nil {
		if err := w.bWriter.Flush(); err != nil {
			return err
		}
	}

	if w.wc.Compress && w.gWriter != nil {
		if err := w.gWriter.Flush(); err != nil {
			return err
		}
	}

	return nil
}

// Close flushes and closes the writer and the associated file handles.
func (w *unixSocketWriter) Close(numRecords int64) (name string, size int64) {

	if w.wc.Buffer {
		flushWriters(w.bWriter)
	}

	if w.wc.Compress {
		closeGzipWriters(w.gWriter)
	}

	err := w.conn.Close()
	if err != nil {
		ioLog.Error("failed to close unix socket connection", zap.Error(err))
	}

	return w.wc.Name, 0
}
