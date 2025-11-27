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
