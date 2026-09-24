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

// How much evidence a decoder required before claiming a stream.
//
// The port-independent scan used to take the first decoder that said yes,
// walking ports in ascending order, so a one-byte check on port 21 outranked a
// checksum on port 20000. Measured over one sample per decoder, that sent 5 of
// 29 protocols to the wrong decoder off their own port -- including SMTP, whose
// signature is strictly stronger than the FTP one that took it and which lost
// only because 25 > 21.
//
// These values rank the evidence instead. They are not a confidence that the
// guess is right; they say how much had to match before the guess was made.
const (
	// SpecificityHeuristic is a statistical judgement or a single nibble: no
	// fixed bytes that the protocol guarantees.
	SpecificityHeuristic = 10

	// SpecificityWeak is one to three fixed bytes, a range check, or an
	// unanchored substring.
	SpecificityWeak = 20

	// SpecificityStructural is a field enum plus a length that has to agree
	// with the data present.
	SpecificityStructural = 30

	// SpecificityMagic is four or more fixed bytes, or a literal long enough
	// that it cannot collide.
	SpecificityMagic = 40

	// SpecificityValidated is a checksum, or a complete parse of the message.
	SpecificityValidated = 50
)

// StreamDecoderAPI describes an interface that all stream decoders need to implement
// this allows to supply a custom structure and maintain state for advanced protocol analysis.
type StreamDecoderAPI interface {
	DecoderAPI

	// CanDecodeStream determines if this decoder can understand the protocol used
	CanDecodeStream(client []byte, server []byte) bool

	// MatchSpecificity reports how much evidence this decoder required to
	// accept these bytes. Only meaningful when CanDecodeStream returned true.
	//
	// It takes the data because for several decoders the answer varies with it:
	// s7comm validates an S7 payload on a data-transfer PDU and only a COTP
	// header otherwise, and ENIP carries CIP on some commands and nothing on
	// others. A single number per decoder cannot express that, and those are
	// exactly the cases where the wrong decoder wins.
	MatchSpecificity(client []byte, server []byte) int

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
