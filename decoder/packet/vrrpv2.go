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

var vrrpv2Decoder = newGoPacketDecoder(
	types.Type_NC_VRRPv2,
	layers.LayerTypeVRRP,
	"The Virtual Router Redundancy Protocol is a computer networking protocol that provides for automatic assignment of available Internet Protocol routers to participating hosts",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if vrrpv2, ok := layer.(*layers.VRRPv2); ok {
			var addr []string
			for _, a := range vrrpv2.IPAddress {
				addr = append(addr, a.String())
			}

			return &types.VRRPv2{
				Timestamp:    timestamp,
				Version:      int32(vrrpv2.Version),
				Type:         int32(vrrpv2.Type),
				VirtualRtrID: int32(vrrpv2.VirtualRtrID),
				Priority:     int32(vrrpv2.Priority),
				CountIPAddr:  int32(vrrpv2.CountIPAddr),
				AuthType:     int32(vrrpv2.AuthType),
				AdverInt:     int32(vrrpv2.AdverInt),
				Checksum:     int32(vrrpv2.Checksum),
				IPAddress:    addr,
			}
		}

		return nil
	},
)
