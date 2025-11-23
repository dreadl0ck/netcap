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

var ipv6HopByHopDecoder = newGoPacketDecoder(
	types.Type_NC_IPv6HopByHop,
	layers.LayerTypeIPv6HopByHop,
	"Internet Protocol version 6 (IPv6) is the most recent version of the Internet Protocol (IP), the communications protocol that provides an identification and location system for computers on networks and routes traffic across the Internet",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if ip6hop, ok := layer.(*layers.IPv6HopByHop); ok {
			var options []*types.IPv6HopByHopOption
			for _, o := range ip6hop.Options {
				// Safety check: ensure OptionAlignment has at least 2 elements
				var one, two int32
				if len(o.OptionAlignment) >= 1 {
					one = int32(o.OptionAlignment[0])
				}
				if len(o.OptionAlignment) >= 2 {
					two = int32(o.OptionAlignment[1])
				}

				a := &types.IPv6HopByHopOptionAlignment{
					One: one,
					Two: two,
				}

				options = append(options, &types.IPv6HopByHopOption{
					OptionType:      int32(o.OptionType),
					OptionLength:    int32(o.OptionLength),
					ActualLength:    int32(o.ActualLength),
					OptionData:      o.OptionData,
					OptionAlignment: a,
				})
			}

			return &types.IPv6HopByHop{
				Timestamp: timestamp,
				Options:   options,
			}
		}

		return nil
	},
)
