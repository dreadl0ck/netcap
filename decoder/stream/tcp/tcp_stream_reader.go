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

package tcp

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"go.uber.org/zap"

	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/core"
)

var reassemblyLog = zap.NewNop()

// SetLogger sets the logger instance.
func SetLogger(l *zap.Logger) {
	reassemblyLog = l
}

// tcpStreamReader is an internal structure that is used to read TCP data streams
// this structure has an optimized field order to avoid excessive padding.
type tcpStreamReader struct {
	sync.Mutex
	serviceBanner      bytes.Buffer
	data               core.DataFragments
	ident              string
	parent             *tcpConnection
	numBytes           int
	dataChan           chan *core.StreamData
	serviceBannerBytes int
	hexdump            bool
	isClient           bool
	saved              bool
}

func (t *tcpConnection) newTCPStreamReader(client bool) *tcpStreamReader {
	return &tcpStreamReader{
		dataChan: make(chan *core.StreamData, decoderconfig.Instance.StreamDecoderBufSize),
		ident:    t.ident,
		hexdump:  decoderconfig.Instance.HexDump,
		parent:   t,
		isClient: client,
	}
}

// Read data from stream.
func (t *tcpStreamReader) Read(p []byte) (int, error) {
	data, ok := <-t.dataChan
	if data == nil || !ok {
		return 0, io.EOF
	}

	// copy received data into the passed in buffer
	l := copy(p, data.RawData)

	t.parent.Lock()
	t.numBytes += l
	t.parent.Unlock()

	return l, nil
}

// DataChan returns a channel for sending stream data.
func (t *tcpStreamReader) DataChan() chan *core.StreamData {
	return t.dataChan
}

// StoreData records an immutable stream fragment synchronously with the
// assembler's delivery path.
//
// This used to happen in Read, on the asynchronous reader goroutine. Since
// dataChan is buffered, ReassemblyComplete could run after feedData returned
// but before Read drained the channel, merge an incomplete conversation, set
// wasMerged, and permanently omit the queued fragments. Moving the append here
// means every fragment is visible before feedData returns; the reader goroutine
// now parses and counts bytes but does not mutate the fragment slice.
func (t *tcpStreamReader) StoreData(data *core.StreamData) {
	t.parent.Lock()
	t.data = append(t.data, data)
	t.parent.Unlock()
}

// Cleanup will tear down the stream processing.
func (t *tcpStreamReader) Cleanup(f *connectionFactory) {
	// signal wait group
	f.wg.Done()
	f.Lock()
	f.numActive--
	f.Unlock()
}

// DataSlice will return all gathered data fragments.
// CAUTION: underlying tcpConnection needs to be locked when calling this, and working with the result!
func (t *tcpStreamReader) DataSlice() core.DataFragments {
	return t.data
}

// ClientStream will return the client side of the stream.
func (t *tcpStreamReader) ClientStream() []byte {
	var buf bytes.Buffer

	t.parent.Lock()
	defer t.parent.Unlock()

	// stores c.BannerSize number of bytes of the server side stream
	for _, d := range t.parent.client.DataSlice() {
		for _, b := range d.Raw() {
			buf.WriteByte(b)
		}
	}

	return buf.Bytes()
}

// ServerStream will return the server side of the stream.
func (t *tcpStreamReader) ServerStream() []byte {
	var buf bytes.Buffer

	t.parent.Lock()
	defer t.parent.Unlock()

	// save server stream for banner identification
	// stores c.BannerSize number of bytes of the server side stream
	for _, d := range t.parent.server.DataSlice() {
		for _, b := range d.Raw() {
			buf.WriteByte(b)
		}
	}

	return buf.Bytes()
}

// IsClient will return true if the stream is acting as the client.
func (t *tcpStreamReader) IsClient() bool {
	return t.isClient
}

// SortAndMergeFragments sorts all stream fragments based on their timestamp
// and generate the conversation buffers.
func (t *tcpStreamReader) SortAndMergeFragments() {
	t.parent.sortAndMergeFragments()
}

// Ident returns the stream identifier.
func (t *tcpStreamReader) Ident() string {
	return t.parent.ident
}

// Network returns the network flow.
func (t *tcpStreamReader) Network() gopacket.Flow {
	return t.parent.net
}

// Transport returns the transport flow.
func (t *tcpStreamReader) Transport() gopacket.Flow {
	return t.parent.transport
}

// FirstPacket returns the timestamp of the first packet seen.
func (t *tcpStreamReader) FirstPacket() time.Time {
	return t.parent.firstPacket
}

// Saved indicates whether the stream has already been persisted on disk.
func (t *tcpStreamReader) Saved() bool {
	t.parent.Lock()
	defer t.parent.Unlock()

	return t.saved
}

// NumBytes returns the number of bytes processed.
func (t *tcpStreamReader) NumBytes() int {
	t.parent.Lock()
	defer t.parent.Unlock()

	return t.numBytes
}

// Client returns the client streamReader.
func (t *tcpStreamReader) Client() streamReader {
	return t.parent.client
}

// SetClient will mark this stream as the client.
func (t *tcpStreamReader) SetClient(v bool) {
	t.parent.Lock()
	defer t.parent.Unlock()
	t.isClient = v
}

// MarkSaved will mark this stream as persisted on disk.
func (t *tcpStreamReader) MarkSaved() {
	t.parent.Lock()
	defer t.parent.Unlock()
	t.saved = true
}

// ServiceIdent will return the identifier of the service (serverIP:serverPort).
func (t *tcpStreamReader) ServiceIdent() string {
	t.parent.Lock()
	defer t.parent.Unlock()

	return filepath.Clean(fmt.Sprintf("%s:%s", t.parent.server.Network().Dst(), t.parent.server.Transport().Dst()))
}

// ServiceBanner will return the banner received from the server.
func (t *tcpStreamReader) ServiceBanner() []byte {
	t.parent.Lock()
	defer t.parent.Unlock()

	if t.serviceBanner.Len() == 0 {
		// Save ONLY the first server packet for banner identification
		// Nmap service probes are designed to match against the initial server greeting,
		// not the entire conversation including responses to client commands.
		// This stores up to BannerSize bytes from the FIRST server packet only.
		dataSlice := t.parent.server.DataSlice()
		if len(dataSlice) > 0 {
			// Extract only from the first packet
			firstPacket := dataSlice[0].Raw()
			limit := min(len(firstPacket), decoderconfig.Instance.BannerSize)
			t.serviceBanner.Write(firstPacket[:limit])
			t.serviceBannerBytes = limit
		}
	}

	return t.serviceBanner.Bytes()
}

// Run starts reading TCP traffic in a single direction.
func (t *tcpStreamReader) Run(f *connectionFactory) {
	// defer a cleanup func to flush the requests and responses once the stream encounters an EOF
	defer t.Cleanup(f)

	var (
		err error
		b   = bufio.NewReader(t)
	)

	for {
		err = t.readStream(b)
		if err != nil {
			// exit on EOF
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return
			}

			reassemblyLog.Error("TCP stream encountered an error",
				zap.String("ident", t.parent.ident),
				zap.Error(err),
			)

			// stop processing the stream and trigger cleanup
			return
		}
	}
}

func (t *tcpStreamReader) readStream(b io.ByteReader) error {
	var err error

	for {
		_, err = b.ReadByte()
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return err
		} else if err != nil {
			return err
		}
	}
}

// Merged returns all stream fragments
func (t *tcpStreamReader) Merged() core.DataFragments {
	t.parent.sortAndMergeFragments()

	// via the accessor rather than reading t.parent.merged directly: the slice
	// header is written under the connection lock, and this is called from
	// tcp_stream_processor while the connection's reader goroutines may still
	// be running.
	return t.parent.mergedFragments()
}

// DecodeConversation invokes decode on the parent TCP connection.
func (t *tcpStreamReader) DecodeConversation() {
	t.parent.decode()
}
