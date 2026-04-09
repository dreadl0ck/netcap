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
