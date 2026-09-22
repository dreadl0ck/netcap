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

// icmpv4TypeNames maps ICMP types to human-readable names
var icmpv4TypeNames = map[uint8]string{
	0:  "Echo Reply",
	3:  "Destination Unreachable",
	4:  "Source Quench",
	5:  "Redirect",
	8:  "Echo Request",
	9:  "Router Advertisement",
	10: "Router Solicitation",
	11: "Time Exceeded",
	12: "Parameter Problem",
	13: "Timestamp Request",
	14: "Timestamp Reply",
	15: "Information Request",
	16: "Information Reply",
	17: "Address Mask Request",
	18: "Address Mask Reply",
}

var icmpv4Decoder = newGoPacketDecoder(
	types.Type_NC_ICMPv4,
	layers.LayerTypeICMPv4,
	"The Internet Control Message Protocol (ICMP) is a supporting protocol in the Internet protocol suite",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if icmp4, ok := layer.(*layers.ICMPv4); ok {
			// Extract type and code from TypeCode
			icmpType := uint8(icmp4.TypeCode >> 8)
			icmpCode := uint8(icmp4.TypeCode & 0xFF)

			// Calculate payload entropy if configured
			var payloadEntropy float64
			if conf.CalculateEntropy {
				payloadEntropy = entropy(icmp4.Payload)
			}

			// Get type name
			typeName := icmpv4TypeNames[icmpType]
			if typeName == "" {
				typeName = "Unknown"
			}

			// Capture payload if configured (for tunneling/covert channel detection)
			var payload []byte
			if conf.IncludePayloads {
				payload = icmp4.Payload
			}

			return &types.ICMPv4{
				Timestamp:            timestamp,
				TypeCode:             int32(icmp4.TypeCode),
				Checksum:             int32(icmp4.Checksum),
				Id:                   int32(icmp4.Id),
				Seq:                  int32(icmp4.Seq),
				PayloadSize:          int32(len(icmp4.Payload)),
				PayloadEntropy:       payloadEntropy,
				TypeName:             typeName,
				Type:                 int32(icmpType),
				Code:                 int32(icmpCode),
				IsRedirect:           icmpType == 5,
				IsTimestampRequest:   icmpType == 13,
				IsAddressMaskRequest: icmpType == 17,
				IsEchoRequest:        icmpType == 8,
				IsEchoReply:          icmpType == 0,
				IsDestUnreachable:    icmpType == 3,
				IsTimeExceeded:       icmpType == 11,
				Payload:              payload,
			}
		}

		return nil
	},
)
