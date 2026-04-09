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

var mldv2QueryDecoder = newGoPacketDecoder(
	types.Type_NC_MLDv2MulticastListenerQuery,
	layers.LayerTypeMLDv2MulticastListenerQuery,
	"MLDv2 Multicast Listener Query is sent by multicast routers to query the multicast listening state of neighboring interfaces (RFC 3810)",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if mld, ok := layer.(*layers.MLDv2MulticastListenerQueryMessage); ok {
			sourceAddrs := make([]string, 0, len(mld.SourceAddresses))
			for _, ip := range mld.SourceAddresses {
				sourceAddrs = append(sourceAddrs, ip.String())
			}

			// Determine query type based on RFC 3810
			multicastAddrStr := mld.MulticastAddress.String()
			isGeneralQuery := multicastAddrStr == "::" || mld.MulticastAddress.IsUnspecified()
			hasSourceAddresses := len(mld.SourceAddresses) > 0
			isGroupSpecificQuery := !isGeneralQuery && !hasSourceAddresses
			isGroupAndSourceQuery := !isGeneralQuery && hasSourceAddresses

			return &types.MLDv2MulticastListenerQuery{
				Timestamp:                    timestamp,
				MaximumResponseCode:          int32(mld.MaximumResponseCode),
				MulticastAddress:             multicastAddrStr,
				SuppressRoutersideProcessing: mld.SuppressRoutersideProcessing,
				QueriersRobustnessVariable:   int32(mld.QueriersRobustnessVariable),
				QueriersQueryIntervalCode:    int32(mld.QueriersQueryIntervalCode),
				NumberOfSources:              int32(mld.NumberOfSources),
				SourceAddresses:              sourceAddrs,
				IsGeneralQuery:               isGeneralQuery,
				IsGroupSpecificQuery:         isGroupSpecificQuery,
				IsGroupAndSourceQuery:        isGroupAndSourceQuery,
			}
		}

		return nil
	},
)
