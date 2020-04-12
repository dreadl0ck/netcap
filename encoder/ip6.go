/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package encoder

import (
	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/gopacket/layers"
	"github.com/dreadl0ck/netcap/types"
	"github.com/golang/protobuf/proto"
)

var ipv6Encoder = CreateLayerEncoder(
	types.Type_NC_IPv6,
	layers.LayerTypeIPv6,
	func(layer gopacket.Layer, timestamp string) proto.Message {
		if ip6, ok := layer.(*layers.IPv6); ok {
			return &types.IPv6{
				Timestamp:      timestamp,
				Version:        int32(ip6.Version),
				TrafficClass:   int32(ip6.TrafficClass),
				FlowLabel:      uint32(ip6.FlowLabel),
				Length:         int32(ip6.Length),
				NextHeader:     int32(ip6.NextHeader),
				HopLimit:       int32(ip6.HopLimit),
				SrcIP:          ip6.SrcIP.String(),
				DstIP:          ip6.DstIP.String(),
				PayloadSize:    int32(len(ip6.Payload)),
				PayloadEntropy: Entropy(ip6.Payload),
			}
		}
		return nil
	})
