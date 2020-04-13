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

package encoder

import (
	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/gopacket/layers"
	"github.com/dreadl0ck/netcap/types"
	"github.com/golang/protobuf/proto"
)

var linkLayerDiscoveryEncoder = CreateLayerEncoder(
	types.Type_NC_LinkLayerDiscovery,
	layers.LayerTypeLinkLayerDiscovery,
	func(layer gopacket.Layer, timestamp string) proto.Message {
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
	})
