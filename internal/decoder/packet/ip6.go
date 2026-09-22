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

// ipv6NextHeaderNames maps next header values to names
var ipv6NextHeaderNames = map[layers.IPProtocol]string{
	layers.IPProtocolTCP:             "TCP",
	layers.IPProtocolUDP:             "UDP",
	layers.IPProtocolICMPv6:          "ICMPv6",
	layers.IPProtocolSCTP:            "SCTP",
	layers.IPProtocolGRE:             "GRE",
	layers.IPProtocolIPv6HopByHop:    "Hop-by-Hop",
	layers.IPProtocolIPv6Routing:     "Routing",
	layers.IPProtocolIPv6Fragment:    "Fragment",
	layers.IPProtocolIPv6Destination: "Destination",
	layers.IPProtocolNoNextHeader:    "No Next Header",
}

var ipv6Decoder = newGoPacketDecoder(
	types.Type_NC_IPv6,
	layers.LayerTypeIPv6,
	"Internet Protocol version 6 (IPv6) is the most recent version of the Internet Protocol (IP), the communications protocol that provides an identification and location system for computers on networks and routes traffic across the Internet",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if ip6, ok := layer.(*layers.IPv6); ok {
			var e float64
			if conf.CalculateEntropy {
				e = entropy(ip6.Payload)
			}

			// Get next header name
			nextHeaderName := ipv6NextHeaderNames[ip6.NextHeader]
			if nextHeaderName == "" {
				nextHeaderName = "Unknown"
			}

			// Extract DSCP and ECN from TrafficClass
			dscp := int32(ip6.TrafficClass >> 2)
			ecn := int32(ip6.TrafficClass & 0x03)

			// Check if this is a fragment (NextHeader == 44)
			isFragment := ip6.NextHeader == layers.IPProtocolIPv6Fragment

			return &types.IPv6{
				Timestamp:           timestamp,
				Version:             int32(ip6.Version),
				TrafficClass:        int32(ip6.TrafficClass),
				FlowLabel:           ip6.FlowLabel,
				Length:              int32(ip6.Length),
				NextHeader:          int32(ip6.NextHeader),
				HopLimit:            int32(ip6.HopLimit),
				SrcIP:               ip6.SrcIP.String(),
				DstIP:               ip6.DstIP.String(),
				PayloadSize:         int32(len(ip6.Payload)),
				PayloadEntropy:      e,
				NextHeaderName:      nextHeaderName,
				HasExtensionHeaders: ip6.NextHeader == layers.IPProtocolIPv6HopByHop,
				IsFragment:          isFragment,
				DSCP:                dscp,
				ECN:                 ecn,
			}
		}

		return nil
	},
)
