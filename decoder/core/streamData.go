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

import (
	"github.com/dreadl0ck/gopacket"

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

	// udp specific fields
	CaptureInformation gopacket.CaptureInfo
	Net                gopacket.Flow
	Trans              gopacket.Flow
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
