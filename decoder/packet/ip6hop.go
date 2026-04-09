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

var ipv6HopByHopDecoder = newGoPacketDecoder(
	types.Type_NC_IPv6HopByHop,
	layers.LayerTypeIPv6HopByHop,
	"Internet Protocol version 6 (IPv6) is the most recent version of the Internet Protocol (IP), the communications protocol that provides an identification and location system for computers on networks and routes traffic across the Internet",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if ip6hop, ok := layer.(*layers.IPv6HopByHop); ok {
			var options []*types.IPv6HopByHopOption
			for _, o := range ip6hop.Options {
				// Safety check: ensure OptionAlignment has at least 2 elements
				var one, two int32
				if len(o.OptionAlignment) >= 1 {
					one = int32(o.OptionAlignment[0])
				}
				if len(o.OptionAlignment) >= 2 {
					two = int32(o.OptionAlignment[1])
				}

				a := &types.IPv6HopByHopOptionAlignment{
					One: one,
					Two: two,
				}

				options = append(options, &types.IPv6HopByHopOption{
					OptionType:      int32(o.OptionType),
					OptionLength:    int32(o.OptionLength),
					ActualLength:    int32(o.ActualLength),
					OptionData:      o.OptionData,
					OptionAlignment: a,
				})
			}

			return &types.IPv6HopByHop{
				Timestamp: timestamp,
				Options:   options,
			}
		}

		return nil
	},
)
