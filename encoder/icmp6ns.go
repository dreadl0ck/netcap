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
	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/gopacket/layers"
)

var icmpv6NeighborSolicitationEncoder = CreateLayerEncoder(
	types.Type_NC_ICMPv6NeighborSolicitation,
	layers.LayerTypeICMPv6NeighborSolicitation,
	func(layer gopacket.Layer, timestamp string) proto.Message {
		if icmp6ns, ok := layer.(*layers.ICMPv6NeighborSolicitation); ok {
			var opts []*types.ICMPv6Option
			for _, o := range icmp6ns.Options {
				opts = append(opts, &types.ICMPv6Option{
					Data: o.Data,
					Type: int32(o.Type),
				})
			}
			return &types.ICMPv6NeighborSolicitation{
				Timestamp:     timestamp,
				TargetAddress: icmp6ns.TargetAddress.String(),
				Options:       opts,
			}
		}
		return nil
	})
