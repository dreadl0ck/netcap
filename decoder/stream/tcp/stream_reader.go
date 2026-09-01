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
	"time"

	"github.com/gopacket/gopacket"

	"github.com/dreadl0ck/netcap/decoder/core"
)

// streamReader is an interface for processing a uni-directional stream of TCP network data
// it defines to manage a stream lifecycle and is used to close the remaining open streams
// and process the remaining data when the engine is stopped.
type streamReader interface {

	// Read data from stream.
	Read(p []byte) (int, error)

	// Run starts processing the stream.
	Run(f *connectionFactory)

	// DataChan returns a channel for sending stream data.
	DataChan() chan *core.StreamData

	// StoreData records a fragment before it is queued for asynchronous stream
	// parsing. Recording synchronously guarantees ReassemblyComplete sees every
	// fragment that ReassembledSG delivered, even while the reader goroutine is
	// still draining its buffered channel.
	StoreData(*core.StreamData)

	// DataSlice will return all gathered data fragments.
	DataSlice() core.DataFragments

	// Cleanup will tear down the stream processing.
	Cleanup(f *connectionFactory)

	// ClientStream will return the client side of the stream.
	ClientStream() []byte

	// ServerStream will return the server side of the stream.
	ServerStream() []byte

	// IsClient will return true if the stream is acting as the client.
	IsClient() bool

	// SetClient will mark this stream as the client.
	SetClient(bool)

	// Ident returns the stream identifier.
	Ident() string

	// Merged returns the sorted conversation
	Merged() core.DataFragments

	// Network returns the network flow.
	Network() gopacket.Flow

	// Transport returns the transport flow.
	Transport() gopacket.Flow

	// FirstPacket returns the timestamp of the first packet seen.
	FirstPacket() time.Time

	// Saved indicates whether the stream has already been persisted on disk.
	Saved() bool

	// NumBytes returns the number of bytes processed.
	NumBytes() int

	// Client returns the client streamReader.
	Client() streamReader

	// ServiceBanner will return the banner received from the server.
	ServiceBanner() []byte

	// MarkSaved will mark this stream as persisted on disk.
	MarkSaved()

	// ServiceIdent will return the identifier of the service (serverIP:serverPort).
	ServiceIdent() string

	// SortAndMergeFragments sorts all stream fragments based on their timestamp
	// and generate the conversation buffers.
	SortAndMergeFragments()

	// DecodeConversation is used to invoke the protocol decoding
	DecodeConversation()
}
