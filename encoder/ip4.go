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
	"github.com/dreadl0ck/netcap/types"
	"github.com/golang/protobuf/proto"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var IPv4Encoder = CreateLayerEncoder(
	types.Type_NC_IPv4,
	layers.LayerTypeIPv4,
	func(layer gopacket.Layer, timestamp string) proto.Message {
		if ip4, ok := layer.(*layers.IPv4); ok {

			var opts []*types.IPv4Option
			for _, o := range ip4.Options {
				opts = append(opts, &types.IPv4Option{
					OptionData:   o.OptionData,
					OptionLength: int32(o.OptionLength),
					OptionType:   int32(o.OptionType),
				})
			}
			return &types.IPv4{
				Timestamp:      timestamp,
				Version:        int32(ip4.Version),
				IHL:            int32(ip4.IHL),
				TOS:            int32(ip4.TOS),
				Length:         int32(ip4.Length),
				Id:             int32(ip4.Id),
				Flags:          int32(ip4.Flags),
				FragOffset:     int32(ip4.FragOffset),
				TTL:            int32(ip4.TTL),
				Protocol:       int32(ip4.Protocol),
				Checksum:       int32(ip4.Checksum),
				SrcIP:          ip4.SrcIP.String(),
				DstIP:          ip4.DstIP.String(),
				Padding:        ip4.Padding,
				Options:        opts,
				PayloadEntropy: Entropy(ip4.Payload),
				PayloadSize:    int32(len(ip4.Payload)),
			}
		}
		return nil
	})
