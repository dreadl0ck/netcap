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
			}
		}

		return nil
	},
)
