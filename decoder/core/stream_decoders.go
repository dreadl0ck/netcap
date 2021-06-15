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

package core

// TransportProtocol is a layer 4 protocol from the OSI model
type TransportProtocol int

const (
	// TCP protocol
	TCP TransportProtocol = iota
	// UDP protocol
	UDP
	// All will invoke decoder for all transport protocols
	All
)

// StreamDecoderAPI describes an interface that all stream decoders need to implement
// this allows to supply a custom structure and maintain state for advanced protocol analysis.
type StreamDecoderAPI interface {
	DecoderAPI

	// CanDecodeStream determines if this decoder can understand the protocol used
	CanDecodeStream(client []byte, server []byte) bool

	// GetReaderFactory returns a factory for processing streams of the current decoder
	GetReaderFactory() StreamDecoderFactory

	Transport() TransportProtocol
}

// StreamDecoderFactory produces stream decoder instances.
type StreamDecoderFactory interface {

	// New StreamDecoderInterface
	New(conversation *ConversationInfo) StreamDecoderInterface
}

// StreamDecoderInterface is the interface for processing a bi-directional network connection.
type StreamDecoderInterface interface {

	// Decode parses the stream according to the identified protocol.
	Decode()
}
