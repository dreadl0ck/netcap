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
	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/dreadl0ck/netcap/types"
)

// icmpv6TypeNames maps ICMPv6 types to human-readable names
var icmpv6TypeNames = map[uint8]string{
	1:   "Destination Unreachable",
	2:   "Packet Too Big",
	3:   "Time Exceeded",
	4:   "Parameter Problem",
	128: "Echo Request",
	129: "Echo Reply",
	130: "Multicast Listener Query",
	131: "Multicast Listener Report",
	132: "Multicast Listener Done",
	133: "Router Solicitation",
	134: "Router Advertisement",
	135: "Neighbor Solicitation",
	136: "Neighbor Advertisement",
	137: "Redirect",
	138: "Router Renumbering",
	139: "ICMP Node Info Query",
	140: "ICMP Node Info Response",
}

var icmpv6Decoder = newGoPacketDecoder(
	types.Type_NC_ICMPv6,
	layers.LayerTypeICMPv6,
	"The Internet Control Message Protocol (ICMP) is a supporting protocol in the Internet protocol suite",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if icmp6, ok := layer.(*layers.ICMPv6); ok {
			// Extract type and code from TypeCode
			icmpType := uint8(icmp6.TypeCode >> 8)
			icmpCode := uint8(icmp6.TypeCode & 0xFF)

			// Calculate payload entropy if configured
			var payloadEntropy float64
			if conf.CalculateEntropy {
				payloadEntropy = entropy(icmp6.Payload)
			}

			// Get type name
			typeName := icmpv6TypeNames[icmpType]
			if typeName == "" {
				typeName = "Unknown"
			}

			// Capture payload if configured (for tunneling/covert channel detection)
			var payload []byte
			if conf.IncludePayloads {
				payload = icmp6.Payload
			}

			return &types.ICMPv6{
				Timestamp:               timestamp,
				TypeCode:                int32(icmp6.TypeCode),
				Checksum:                int32(icmp6.Checksum),
				PayloadSize:             int32(len(icmp6.Payload)),
				PayloadEntropy:          payloadEntropy,
				TypeName:                typeName,
				Type:                    int32(icmpType),
				Code:                    int32(icmpCode),
				IsRedirect:              icmpType == 137,
				IsRouterSolicitation:    icmpType == 133,
				IsRouterAdvertisement:   icmpType == 134,
				IsNeighborSolicitation:  icmpType == 135,
				IsNeighborAdvertisement: icmpType == 136,
				IsEchoRequest:           icmpType == 128,
				IsEchoReply:             icmpType == 129,
				Payload:                 payload,
			}
		}

		return nil
	},
)
