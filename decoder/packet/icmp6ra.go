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
	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/gopacket/layers"
	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/types"
)

var icmpv6RouterAdvertisementDecoder = newGoPacketDecoder(
	types.Type_NC_ICMPv6RouterAdvertisement,
	layers.LayerTypeICMPv6RouterAdvertisement,
	"The Internet Control Message Protocol (ICMP) is a supporting protocol in the Internet protocol suite",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if icmp6ra, ok := layer.(*layers.ICMPv6RouterAdvertisement); ok {
			var opts []*types.ICMPv6Option
			for _, o := range icmp6ra.Options {
				opts = append(opts, &types.ICMPv6Option{
					Data: o.Data,
					Type: int32(o.Type),
				})
			}

			return &types.ICMPv6RouterAdvertisement{
				Timestamp:      timestamp,
				HopLimit:       int32(icmp6ra.HopLimit),
				Flags:          int32(icmp6ra.Flags),
				RouterLifetime: int32(icmp6ra.RouterLifetime),
				ReachableTime:  icmp6ra.ReachableTime,
				RetransTimer:   icmp6ra.RetransTimer,
				Options:        opts,
			}
		}

		return nil
	},
)
