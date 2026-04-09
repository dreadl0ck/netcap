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

package packet

import (
	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/dreadl0ck/netcap/types"
)

var ip6FragmentDecoder = newGoPacketDecoder(
	types.Type_NC_IPv6Fragment,
	layers.LayerTypeIPv6Fragment,
	"IPv6 fragmented packet",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if ip6f, ok := layer.(*layers.IPv6Fragment); ok {
			return &types.IPv6Fragment{
				Timestamp:      timestamp,
				NextHeader:     int32(ip6f.NextHeader),
				Reserved1:      int32(ip6f.Reserved1),
				FragmentOffset: int32(ip6f.FragmentOffset),
				Reserved2:      int32(ip6f.Reserved2),
				MoreFragments:  ip6f.MoreFragments,
				Identification: ip6f.Identification,
			}
		}

		return nil
	},
)
