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
	"bytes"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/internal/aggregate"
	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/reassembly"
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
	data               core.DataFragments
	stored             *storedTCPReader
	storedMarkers      map[*core.StreamData]uint64
	ident              string
	parent             *tcpConnection
	numBytes           int
	dataChan           chan *core.StreamData
	hexdump            bool
	isClient           bool
	saved              bool
	closeOnce          sync.Once
	done               chan struct{}
	factorySlot        int
	synchronousFactory *connectionFactory
}

func (t *tcpConnection) newTCPStreamReader(client bool) *tcpStreamReader {
	return &tcpStreamReader{
		ident:       t.ident,
		hexdump:     decoderconfig.Instance.HexDump,
		parent:      t,
		isClient:    client,
		done:        make(chan struct{}),
		factorySlot: -1,
	}
}

// DataChan returns a channel for sending stream data.
func (t *tcpStreamReader) DataChan() chan *core.StreamData {
	return t.dataChan
}

func (t *tcpStreamReader) CloseData() {
	t.closeOnce.Do(func() {
		if t.dataChan != nil {
			close(t.dataChan)
		} else {
			if t.synchronousFactory != nil {
				t.Cleanup(t.synchronousFactory)
			}
			if t.done != nil {
				close(t.done)
			}
		}
	})
}

// StoreData records an immutable stream fragment synchronously with the
// assembler's delivery path so completion sees fragments still queued for draining.
func (t *tcpStreamReader) StoreData(data *core.StreamData) {
	t.parent.Lock()
	defer t.parent.Unlock()
	if t.stored == nil && decoderconfig.Instance != nil && decoderconfig.Instance.AggregateStore != nil && !decoderconfig.Instance.IncrementalHTTP && t.dataChan == nil {
		id := tcpReaderSequence.Add(1)
		t.stored = &storedTCPReader{state: decoderconfig.Instance.AggregateStore, prefix: fmt.Sprintf("tcp/payload/%016x/", id), budget: t.parent.stateBudget, payloadBudget: t.parent.payloadBudget}
	}
	if t.stored != nil {
		if data.DiscardReason != "" {
			if t.storedMarkers == nil {
				t.storedMarkers = map[*core.StreamData]uint64{}
			}
			t.storedMarkers[data] = t.stored.count
		}
		if err := t.stored.append(data); err != nil {
			t.failRead(err)
			return
		}
		if t.stored.loaded {
			t.data = append(t.data, data)
		}
	} else {
		t.data = append(t.data, data)
	}
	t.parent.wasMerged = false
	t.numBytes += len(data.RawData)
}

func (t *tcpStreamReader) updateStoredMarker(data *core.StreamData) {
	t.parent.Lock()
	defer t.parent.Unlock()
	if index, found := t.storedMarkers[data]; found {
		_ = t.stored.state.Do(func(tx *aggregate.Tx) error {
			wire, err := encodeTCPFragment(data)
			if err != nil {
				return err
			}
			return tx.Put(fmt.Sprintf("%s%016x", t.stored.prefix, index), wire)
		})
		if t.stored.loaded {
			for _, fragment := range t.data {
				if stored, ok := fragment.(*core.StreamData); ok && stored.DiscardReason == data.DiscardReason && stored.Dir == data.Dir {
					stored.DiscardedBytes = data.DiscardedBytes
				}
			}
		}
	}
}

// Cleanup will tear down the stream processing.
func (t *tcpStreamReader) Cleanup(f *connectionFactory) {
	f.Lock()
	f.numActive--
	f.Unlock()
	f.wg.Done()
}

// DataSlice will return all gathered data fragments.
// CAUTION: underlying tcpConnection needs to be locked when calling this, and working with the result!
func (t *tcpStreamReader) DataSlice() core.DataFragments {
	data, err := t.DataSliceResult()
	if err != nil {
		t.failRead(err)
	}
	return data
}

func (t *tcpStreamReader) DataSliceResult() (core.DataFragments, error) {
	if t.stored != nil && !t.stored.loaded {
		data, err := t.stored.read()
		if err != nil {
			return nil, err
		}
		t.data, t.stored.loaded = data, true
		for _, fragment := range data {
			t.setFragmentDirection(fragment)
		}
	}
	return t.data, nil
}

func (t *tcpStreamReader) failRead(err error) {
	if t.parent != nil && t.parent.factory != nil {
		t.parent.factory.failIncremental(err)
	}
}

func (t *tcpStreamReader) setFragmentDirection(fragment core.DataFragment) {
	dir := reassembly.TCPDirServerToClient
	if t.isClient {
		dir = reassembly.TCPDirClientToServer
	}
	fragment.SetDirection(dir)
}

func (t *tcpStreamReader) Count() int64 {
	if t.stored != nil && !t.stored.loaded {
		return t.stored.Count()
	}
	return int64(len(t.data))
}

// The connection owner serializes walks with mutation, role changes and retirement.
func (t *tcpStreamReader) Walk(yield func(core.DataFragment) bool) error {
	if t.stored != nil && !t.stored.loaded {
		return t.stored.Walk(func(fragment core.DataFragment) bool { t.setFragmentDirection(fragment); return yield(fragment) })
	}
	return core.SliceSource(t.data).Walk(yield)
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

// NumBytes returns the number of bytes recorded.
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

	limit := min(decoderconfig.Instance.BannerSize, 8192)
	var prefix []byte
	if limit <= 0 {
		return prefix
	}
	err := readerFragments(t.parent.server).Walk(func(fragment core.DataFragment) bool {
		data, ok := fragment.(*core.StreamData)
		if !ok || data.SkippedBytes != 0 || data.DiscardedBytes > 0 {
			return false
		}
		size := min(len(data.Raw()), limit-len(prefix))
		prefix = append(prefix, data.Raw()[:size]...)
		return len(prefix) < limit
	})
	if err != nil {
		t.failRead(err)
		return nil
	}
	return prefix
}

// A greeting can span deliveries, but bytes after a capture gap cannot complete it.
func contiguousServicePrefix(data core.DataFragments, limit int) []byte {
	limit = min(limit, 8192)
	if limit <= 0 {
		return nil
	}
	var prefix []byte
	for _, fragment := range data {
		d, ok := fragment.(*core.StreamData)
		if !ok || d.SkippedBytes != 0 || d.DiscardedBytes > 0 {
			break
		}
		n := min(len(d.Raw()), limit-len(prefix))
		prefix = append(prefix, d.Raw()[:n]...)
		if len(prefix) == limit {
			break
		}
	}
	return prefix
}

// Run starts reading TCP traffic in a single direction.
func (t *tcpStreamReader) Run(f *connectionFactory) {
	defer func() {
		t.Cleanup(f)
		if t.done != nil {
			close(t.done)
		}
	}()
	for range t.dataChan {
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
