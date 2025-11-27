/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017-2020 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package packet

import (
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/types"
)

// greProtocolNames maps GRE protocol types to human-readable names
var greProtocolNames = map[layers.EthernetType]string{
	layers.EthernetTypeIPv4:            "IPv4",
	layers.EthernetTypeIPv6:            "IPv6",
	layers.EthernetTypeARP:             "ARP",
	layers.EthernetTypeDot1Q:           "802.1Q VLAN",
	layers.EthernetTypePPPoEDiscovery:  "PPPoE Discovery",
	layers.EthernetTypePPPoESession:    "PPPoE Session",
	layers.EthernetTypeMPLSUnicast:     "MPLS Unicast",
	layers.EthernetTypeMPLSMulticast:   "MPLS Multicast",
}

var greDecoder = newGoPacketDecoder(
	types.Type_NC_GRE,
	layers.LayerTypeGRE,
	"Generic Routing Encapsulation is a tunneling protocol developed by Cisco Systems that can encapsulate a wide variety of network layer protocols inside virtual point-to-point links or point-to-multipoint links over an Internet Protocol network",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if gre, ok := layer.(*layers.GRE); ok {
			// Get encapsulated payload
			grePayload := layer.LayerPayload()
			payloadSize := int32(len(grePayload))

			// Capture payload if configured (for tunnel inspection)
			var payload []byte
			if conf.IncludePayloads {
				payload = grePayload
			}

			// Get encapsulated protocol name
			encapProto := greProtocolNames[gre.Protocol]
			if encapProto == "" {
				encapProto = "Unknown"
			}

			return &types.GRE{
				Timestamp:           timestamp,
				ChecksumPresent:     gre.ChecksumPresent,
				RoutingPresent:      gre.RoutingPresent,
				KeyPresent:          gre.KeyPresent,
				SeqPresent:          gre.SeqPresent,
				StrictSourceRoute:   gre.StrictSourceRoute,
				AckPresent:          gre.AckPresent,
				RecursionControl:    int32(gre.RecursionControl),
				Flags:               int32(gre.Flags),
				Version:             int32(gre.Version),
				Protocol:            int32(gre.Protocol),
				Checksum:            int32(gre.Checksum),
				Offset:              int32(gre.Offset),
				Key:                 gre.Key,
				Seq:                 gre.Seq,
				Ack:                 gre.Ack,
				// @TODO: DEBUG nil pointer exception when acessing gre.Next
				// Routing: encodeGRERouting(gre.AddressFamily, gre.SREOffset, gre.SRELength, gre.RoutingInformation, nil),
				// Encapsulated payload for tunnel inspection
				Payload:             payload,
				PayloadSize:         payloadSize,
				EncapsulatedProtocol: encapProto,
			}
		}

		return nil
	},
)

func encodeGRERouting(addressFamily uint16, SREOffset, SRELength uint8, RoutingInformation []byte, next *layers.GRERouting) *types.GRERouting {
	var r *types.GRERouting
	if next != nil {
		r = encodeGRERouting(next.AddressFamily, next.SREOffset, next.SRELength, next.RoutingInformation, next.Next)
	}

	return &types.GRERouting{
		AddressFamily:      int32(addressFamily),
		SREOffset:          int32(SREOffset),
		SRELength:          int32(SRELength),
		RoutingInformation: RoutingInformation,
		Next:               r,
	}
}
