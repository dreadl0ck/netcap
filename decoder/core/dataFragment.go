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

// dataFragment describes functionality of encapsulation structures for network data fragments.
type dataFragment interface {
	Raw() []byte
	Context() reassembly.AssemblerContext
	Direction() reassembly.TCPFlowDirection
	SetDirection(reassembly.TCPFlowDirection)
	CaptureInfo() gopacket.CaptureInfo
	Network() gopacket.Flow
	Transport() gopacket.Flow
}
