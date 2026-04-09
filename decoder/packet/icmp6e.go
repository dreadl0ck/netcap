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

var icmpv6EchoDecoder = newGoPacketDecoder(
	types.Type_NC_ICMPv6Echo,
	layers.LayerTypeICMPv6Echo,
	"The Internet Control Message Protocol (ICMP) is a supporting protocol in the Internet protocol suite",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if icmp6e, ok := layer.(*layers.ICMPv6Echo); ok {
			// Get echo payload data (for tunneling/covert channel detection)
			echoPayload := layer.LayerPayload()
			payloadSize := int32(len(echoPayload))

			// Calculate payload entropy if configured
			var payloadEntropy float64
			if conf.CalculateEntropy && len(echoPayload) > 0 {
				payloadEntropy = entropy(echoPayload)
			}

			// Capture payload if configured
			var payload []byte
			if conf.IncludePayloads {
				payload = echoPayload
			}

			return &types.ICMPv6Echo{
				Timestamp:      timestamp,
				Identifier:     int32(icmp6e.Identifier),
				SeqNumber:      int32(icmp6e.SeqNumber),
				Payload:        payload,
				PayloadSize:    payloadSize,
				PayloadEntropy: payloadEntropy,
			}
		}

		return nil
	},
)
