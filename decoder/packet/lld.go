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

var linkLayerDiscoveryDecoder = newGoPacketDecoder(
	types.Type_NC_LinkLayerDiscovery,
	layers.LayerTypeLinkLayerDiscovery,
	"The Link Layer Discovery Protocol is a vendor-neutral link layer protocol used by network devices for advertising their identity, capabilities, and neighbors on a local area network based on IEEE 802 technology, principally wired Ethernet",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if lld, ok := layer.(*layers.LinkLayerDiscovery); ok {
			var vals []*types.LinkLayerDiscoveryValue
			for _, v := range lld.Values {
				vals = append(vals, &types.LinkLayerDiscoveryValue{
					Type:   int32(v.Type),
					Length: int32(v.Length),
					Value:  v.Value,
				})
			}

			return &types.LinkLayerDiscovery{
				Timestamp: timestamp,
				ChassisID: &types.LLDPChassisID{
					Subtype: int32(lld.ChassisID.Subtype),
					ID:      lld.ChassisID.ID,
				},
				PortID: &types.LLDPPortID{
					Subtype: int32(lld.PortID.Subtype),
					ID:      lld.PortID.ID,
				},
				TTL:    int32(lld.TTL),
				Values: vals,
			}
		}

		return nil
	},
)
