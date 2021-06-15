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

package tcp

import (
	"time"

	"github.com/dreadl0ck/gopacket"

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
