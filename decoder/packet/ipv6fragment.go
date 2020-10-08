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

var ip6FragmentDecoder = newGoPacketDecoder(
	types.Type_NC_IPv6Fragment,
	layers.LayerTypeIPv6Fragment,
	"IPv6 fragmented packet",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if ip6f, ok := layer.(*layers.IPv6Fragment); ok {
			return &types.IPv6Fragment{
				Timestamp:      timestamp,
				NextHeader:     int32(ip6f.NextHeader),
				Reserved1:      int32(ip6f.Reserved1),
				FragmentOffset: int32(ip6f.FragmentOffset),
				Reserved2:      int32(ip6f.Reserved2),
				MoreFragments:  ip6f.MoreFragments,
				Identification: ip6f.Identification,
			}
		}

		return nil
	},
)
