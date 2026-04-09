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

var udpDecoder = newGoPacketDecoder(
	types.Type_NC_UDP,
	layers.LayerTypeUDP,
	"User Datagram Protocol (UDP) is a connectionless communications protocol, that facilitates the exchange of messages between computing devices in a network",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if udp, ok := layer.(*layers.UDP); ok {
			var payload []byte
			if conf.IncludePayloads {
				payload = layer.LayerPayload()
			}
			var e float64
			if conf.CalculateEntropy {
				e = entropy(udp.Payload)
			}

			return &types.UDP{
				Timestamp:      timestamp,
				SrcPort:        int32(udp.SrcPort),
				DstPort:        int32(udp.DstPort),
				Length:         int32(udp.Length),
				Checksum:       int32(udp.Checksum),
				PayloadEntropy: e,
				PayloadSize:    int32(len(udp.Payload)),
				Payload:        payload,
			}
		}

		return nil
	},
)
