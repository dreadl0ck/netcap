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

import "github.com/dreadl0ck/gopacket"

type packetInfo struct {
	p         gopacket.Packet
	timestamp string
	srcMAC    string
	dstMAC    string
	srcIP     string
	dstIP     string
}

func newPacketInfo(p gopacket.Packet) *packetInfo {
	i := new(packetInfo)

	i.timestamp = p.Metadata().Timestamp.UTC().String()
	i.p = p
	if ll := p.LinkLayer(); ll != nil {
		i.srcMAC = ll.LinkFlow().Src().String()
		i.dstMAC = ll.LinkFlow().Dst().String()
	}
	if nl := p.NetworkLayer(); nl != nil {
		i.srcIP = nl.NetworkFlow().Src().String()
		i.dstIP = nl.NetworkFlow().Dst().String()
	}

	return i
}
