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

var igmpDecoder = newGoPacketDecoder(
	types.Type_NC_IGMP,
	layers.LayerTypeIGMP,
	"The Internet Group Management Protocol (IGMP) is a communications protocol used by hosts and adjacent routers on IPv4 networks to establish multicast group memberships",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if igmp, ok := layer.(*layers.IGMP); ok {
			addresses := make([]string, 0, len(igmp.SourceAddresses))
			for _, ip := range igmp.SourceAddresses {
				addresses = append(addresses, ip.String())
			}
			records := make([]*types.IGMPv3GroupRecord, 0, len(igmp.GroupRecords))
			for _, r := range igmp.GroupRecords {
				srca := make([]string, 0, len(r.SourceAddresses))
				for _, ip := range r.SourceAddresses {
					srca = append(srca, ip.String())
				}
				records = append(records, &types.IGMPv3GroupRecord{
					Type:             int32(r.Type),
					AuxDataLen:       int32(r.AuxDataLen),
					NumberOfSources:  int32(r.NumberOfSources),
					MulticastAddress: r.MulticastAddress.String(),
					SourceAddresses:  srca,
				})
			}

			return &types.IGMP{
				Timestamp:               timestamp,
				Type:                    int32(igmp.Type),
				MaxResponseTime:         uint64(igmp.MaxResponseTime),
				Checksum:                int32(igmp.Checksum),
				GroupAddress:            parseIPv4(igmp.GroupAddress),
				SupressRouterProcessing: igmp.SupressRouterProcessing,
				RobustnessValue:         int32(igmp.RobustnessValue),
				IntervalTime:            uint64(igmp.IntervalTime),
				SourceAddresses:         addresses,
				NumberOfGroupRecords:    int32(igmp.NumberOfGroupRecords),
				NumberOfSources:         int32(igmp.NumberOfSources),
				GroupRecords:            records,
				Version:                 int32(igmp.Version),
			}
		}

		return nil
	},
)
