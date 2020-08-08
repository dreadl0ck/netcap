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

package decoder

import (
	"bytes"
	"time"

	"github.com/dreadl0ck/gopacket"

	"github.com/dreadl0ck/netcap/reassembly"
)

// streamReader is an interface for processing a uni-directional stream of TCP network data
// it defines to manage a stream lifecycle and is used to close the remaining open streams
// and process the remaining data when the engine is stopped.
type streamReader interface {

	// Read data from stream.
	Read(p []byte) (int, error)

	// Run starts processing the stream.
	Run(f *tcpConnectionFactory)

	// DataChan returns a channel for sending stream data.
	DataChan() chan *streamData

	// DataSlice will return all gathered data fragments.
	DataSlice() streamDataSlice

	// Cleanup will tear down the stream processing.
	Cleanup(f *tcpConnectionFactory)

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

	// ConversationRaw provides access to the raw entire conversation.
	ConversationRaw() []byte

	// ConversationColored provides access to the ANSI colored entire conversation.
	ConversationColored() []byte

	// SortAndMergeFragments sorts all stream fragments based on their timestamp
	// and generate the conversation buffers.
	SortAndMergeFragments()
}

// streamDecoder is the interface for processing a bi-directional network connection.
type streamDecoder interface {

	// Decode parses the stream according to the identified protocol.
	Decode()
}

// streamData is a fragment of data we received from a streamReader
// its contains the raw bytes as well an assembler context with timestamp information.
type streamData struct {
	raw []byte
	ac  reassembly.AssemblerContext
	dir reassembly.TCPFlowDirection
}

// streamDataSlice implements sort.Interface to sort data fragments based on their timestamps.
type streamDataSlice []*streamData

func (d streamDataSlice) bytes() []byte {
	var b bytes.Buffer

	for _, data := range d {
		b.Write(data.raw)
	}

	return b.Bytes()
}

// Len returns the length.
func (d streamDataSlice) Len() int {
	return len(d)
}

// Less will check if the value at index i is less than the one at index j.
func (d streamDataSlice) Less(i, j int) bool {
	data1 := d[i]
	data2 := d[j]

	if data1.ac == nil || data2.ac == nil {
		return false
	}

	return data1.ac.GetCaptureInfo().Timestamp.Before(data2.ac.GetCaptureInfo().Timestamp)
}

// Swap will flip both values.
func (d streamDataSlice) Swap(i, j int) {
	d[i], d[j] = d[j], d[i]
}

// stream contains both flows for a connection.
// type stream struct {
// 	a gopacket.Flow
// 	b gopacket.Flow
// }
//
// // reverse flips source and destination.
// func (s *stream) reverse() *stream {
// 	return &stream{
// 		s.a.Reverse(),
// 		s.b.Reverse(),
// 	}
// }
//
// func (s *stream) String() string {
// 	return s.a.String() + " : " + s.b.String()
// }
