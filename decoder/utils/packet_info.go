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
