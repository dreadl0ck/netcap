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

import (
	"github.com/gopacket/gopacket"

	"github.com/dreadl0ck/netcap/reassembly"
)

// StreamData is a payload fragment of data we received from a streamReader
// its contains the raw bytes as well an assembler context with timestamp information.
type StreamData struct {
	// raw binary data
	RawData []byte

	// tcp specific fields
	AssemblerContext reassembly.AssemblerContext
	Dir              reassembly.TCPFlowDirection
	SkippedBytes     int // Gap before this fragment; -1 means unknown initial loss.

	// capture metadata of the packet this fragment was taken from, set for TCP and UDP
	CaptureInformation gopacket.CaptureInfo

	// udp specific fields
	Net   gopacket.Flow
	Trans gopacket.Flow
}

// dataFragment interface implementation

// Raw returns the raw byte slice that makes up the data fragment.
func (s *StreamData) Raw() []byte {
	return s.RawData
}

// Context returns the assembler context.
func (s *StreamData) Context() reassembly.AssemblerContext {
	return s.AssemblerContext
}

// Direction returns the direction of the flow.
func (s *StreamData) Direction() reassembly.TCPFlowDirection {
	return s.Dir
}

// SetDirection will update the flow direction.
func (s *StreamData) SetDirection(d reassembly.TCPFlowDirection) {
	s.Dir = d
}

// CaptureInfo returns the capture information from gopacket
func (s *StreamData) CaptureInfo() gopacket.CaptureInfo {
	return s.CaptureInformation
}

// Network returns the network layer
func (s *StreamData) Network() gopacket.Flow {
	return s.Net
}

// Transport returns the transport layer
func (s *StreamData) Transport() gopacket.Flow {
	return s.Trans
}
