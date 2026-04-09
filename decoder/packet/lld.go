/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package packet

import (
	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/dreadl0ck/netcap/types"
)

var linkLayerDiscoveryDecoder = newGoPacketDecoder(
	types.Type_NC_LinkLayerDiscovery,
	layers.LayerTypeLinkLayerDiscovery,
	"The Link Layer Discovery Protocol is a vendor-neutral link layer protocol used by network devices for advertising their identity, capabilities, and neighbors on a local area network based on IEEE 802 technology, principally wired Ethernet",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if lld, ok := layer.(*layers.LinkLayerDiscovery); ok {
			vals := make([]*types.LinkLayerDiscoveryValue, 0, len(lld.Values))
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
