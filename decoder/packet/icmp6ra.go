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

var icmpv6RouterAdvertisementDecoder = newGoPacketDecoder(
	types.Type_NC_ICMPv6RouterAdvertisement,
	layers.LayerTypeICMPv6RouterAdvertisement,
	"The Internet Control Message Protocol (ICMP) is a supporting protocol in the Internet protocol suite",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if icmp6ra, ok := layer.(*layers.ICMPv6RouterAdvertisement); ok {
			var opts []*types.ICMPv6Option
			for _, o := range icmp6ra.Options {
				opts = append(opts, &types.ICMPv6Option{
					Data: o.Data,
					Type: int32(o.Type),
				})
			}

			return &types.ICMPv6RouterAdvertisement{
				Timestamp:      timestamp,
				HopLimit:       int32(icmp6ra.HopLimit),
				Flags:          int32(icmp6ra.Flags),
				RouterLifetime: int32(icmp6ra.RouterLifetime),
				ReachableTime:  icmp6ra.ReachableTime,
				RetransTimer:   icmp6ra.RetransTimer,
				Options:        opts,
			}
		}

		return nil
	},
)
