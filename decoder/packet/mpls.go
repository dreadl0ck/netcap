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

var mplsDecoder = newGoPacketDecoder(
	types.Type_NC_MPLS,
	layers.LayerTypeMPLS,
	"Multiprotocol Label Switching is a routing technique in telecommunications networks that directs data from one node to the next based on short path labels rather than long network addresses, thus avoiding complex lookups in a routing table and speeding traffic flows",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if mpls, ok := layer.(*layers.MPLS); ok {
			return &types.MPLS{
				Timestamp:    timestamp,
				Label:        int32(mpls.Label),
				TrafficClass: int32(mpls.TrafficClass),
				StackBottom:  mpls.StackBottom,
				TTL:          int32(mpls.TTL),
			}
		}

		return nil
	},
)
