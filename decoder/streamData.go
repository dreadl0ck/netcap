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
	"github.com/dreadl0ck/gopacket"

	"github.com/dreadl0ck/netcap/reassembly"
)

// streamData is a payload fragment of data we received from a streamReader
// its contains the raw bytes as well an assembler context with timestamp information.
type streamData struct {
	// raw binary data
	rawData []byte

	// tcp specific fields
	ac  reassembly.AssemblerContext
	dir reassembly.TCPFlowDirection

	// udp specific fields
	ci    gopacket.CaptureInfo
	net   gopacket.Flow
	trans gopacket.Flow
}

func (s *streamData) raw() []byte {
	return s.rawData
}

func (s *streamData) context() reassembly.AssemblerContext {
	return s.ac
}

func (s *streamData) direction() reassembly.TCPFlowDirection {
	return s.dir
}

func (s *streamData) setDirection(direction reassembly.TCPFlowDirection) {
	s.dir = direction
}

func (s *streamData) captureInfo() gopacket.CaptureInfo {
	return s.ci
}

func (s *streamData) network() gopacket.Flow {
	return s.net
}

func (s *streamData) transport() gopacket.Flow {
	return s.trans
}
