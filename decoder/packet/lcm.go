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

var lcmDecoder = newGoPacketDecoder(
	types.Type_NC_LCM,
	layers.LayerTypeLCM,
	"LCM is a set of libraries and tools for message passing and data marshaling, targeted at real-time systems where high-bandwidth and low latency are critical",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if lcm, ok := layer.(*layers.LCM); ok {
			return &types.LCM{
				Timestamp:      timestamp,
				Magic:          int32(lcm.Magic),
				SequenceNumber: int32(lcm.SequenceNumber),
				PayloadSize:    int32(lcm.PayloadSize),
				FragmentOffset: int32(lcm.FragmentOffset),
				FragmentNumber: int32(lcm.FragmentNumber),
				TotalFragments: int32(lcm.TotalFragments),
				ChannelName:    lcm.ChannelName,
				Fragmented:     lcm.Fragmented,
			}
		}

		return nil
	},
)
