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

var ciscoDiscoveryDecoder = newGoPacketDecoder(
	types.Type_NC_CiscoDiscovery,
	layers.LayerTypeCiscoDiscovery,
	"Cisco Discovery Protocol is a proprietary Data Link Layer protocol used to share information about other directly connected Cisco equipment, such as the operating system version and IP address",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if ciscoDiscovery, ok := layer.(*layers.CiscoDiscovery); ok {
			values := make([]*types.CiscoDiscoveryValue, 0, len(ciscoDiscovery.Values))
			for _, v := range ciscoDiscovery.Values {
				values = append(values, &types.CiscoDiscoveryValue{
					Type:   int32(v.Type),
					Length: int32(v.Length),
					Value:  v.Value,
				})
			}

			return &types.CiscoDiscovery{
				Timestamp: timestamp,
				Version:   int32(ciscoDiscovery.Version),
				TTL:       int32(ciscoDiscovery.TTL),
				Checksum:  int32(ciscoDiscovery.Checksum),
				Values:    values,
			}
		}

		return nil
	},
)
