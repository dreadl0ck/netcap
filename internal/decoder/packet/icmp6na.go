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

var icmpv6NeighborAdvertisementDecoder = newGoPacketDecoder(
	types.Type_NC_ICMPv6NeighborAdvertisement,
	layers.LayerTypeICMPv6NeighborAdvertisement,
	"The Internet Control Message Protocol (ICMP) is a supporting protocol in the Internet protocol suite",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if icmp6na, ok := layer.(*layers.ICMPv6NeighborAdvertisement); ok {
			opts := make([]*types.ICMPv6Option, 0, len(icmp6na.Options))
			for _, o := range icmp6na.Options {
				opts = append(opts, &types.ICMPv6Option{
					Data: o.Data,
					Type: int32(o.Type),
				})
			}

			return &types.ICMPv6NeighborAdvertisement{
				Timestamp:     timestamp,
				Flags:         int32(icmp6na.Flags),
				TargetAddress: icmp6na.TargetAddress.String(),
				Options:       opts,
			}
		}

		return nil
	},
)
