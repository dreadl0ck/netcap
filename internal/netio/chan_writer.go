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

package netio

import (
	"encoding/binary"
	"errors"
	"sync"

	"go.uber.org/zap"

	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/types"
)

// ErrChanWriterClosed is returned when writing to a closed channel writer.
var ErrChanWriterClosed = errors.New("channel writer closed")

// chanWriter sends each audit record into a channel as one message:
// a uvarint length prefix followed by the serialized protobuf, i.e. exactly
// one record in the delimited format that .ncap files use. Concatenating
// messages therefore yields a valid record stream.
//
// The file header is not sent: the receiver writes its own.
type chanWriter struct {
	mu     sync.Mutex
	ch     chan []byte
	closed bool
	wc     *WriterConfig
}

// newChanWriter initializes and configures a new chanWriter instance.
func newChanWriter(wc *WriterConfig) *chanWriter {
	if wc.Buffer || wc.Compress {
		panic("buffering or compression cannot be activated when running using writeChan")
	}
	ioLog.Info("create chanWriter", zap.String("type", wc.Type.String()))

	return &chanWriter{ch: make(chan []byte, wc.ChanSize), wc: wc}
}

// Write sends one length-delimited record into the channel.
func (w *chanWriter) Write(msg proto.Message) error {
	data, err := proto.Marshal(msg)
	if err != nil {
		return err
	}

	rec := make([]byte, 0, binary.MaxVarintLen64+len(data))
	rec = binary.AppendUvarint(rec, uint64(len(data)))
	rec = append(rec, data...)

	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return ErrChanWriterClosed
	}
	w.ch <- rec

	return nil
}

// WriteHeader is a no-op: the receiving side writes the file header.
func (w *chanWriter) WriteHeader(_ types.Type) error {
	return nil
}

// Flush is a no-op for the channel writer since data is immediately sent to the channel.
func (w *chanWriter) Flush() error {
	return nil
}

// Close closes the channel so consumers can drain and finish.
func (w *chanWriter) Close(_ int64) (name string, size int64) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.closed {
		w.closed = true
		close(w.ch)
	}

	return w.wc.Name, 0
}

// GetChan returns a channel for receiving length-delimited records.
func (w *chanWriter) GetChan() <-chan []byte {
	return w.ch
}
