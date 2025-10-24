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

package utils

import (
	"github.com/gopacket/gopacket"
)

// PacketInfo contains packet meta information.
type PacketInfo struct {
	Packet    gopacket.Packet
	Timestamp int64
	SrcMAC    string
	DstMAC    string
	SrcIP     string
	DstIP     string
}

// NewPacketInfo returns a new packet summary
func NewPacketInfo(p gopacket.Packet) *PacketInfo {
	i := new(PacketInfo)

	i.Timestamp = p.Metadata().Timestamp.UnixNano()
	i.Packet = p

	if ll := p.LinkLayer(); ll != nil {
		if len(ll.LinkFlow().Src().Raw()) > 0 {
			i.SrcMAC = ll.LinkFlow().Src().String()
		}
		if len(ll.LinkFlow().Dst().Raw()) > 0 {
			i.DstMAC = ll.LinkFlow().Dst().String()
		}
	}

	if nl := p.NetworkLayer(); nl != nil {
		if len(nl.NetworkFlow().Src().Raw()) > 0 {
			i.SrcIP = nl.NetworkFlow().Src().String()
		}
		if len(nl.NetworkFlow().Dst().Raw()) > 0 {
			i.DstIP = nl.NetworkFlow().Dst().String()
		}
	}

	return i
}
