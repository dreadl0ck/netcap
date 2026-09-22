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

var vxlanDecoder = newGoPacketDecoder(
	types.Type_NC_VXLAN,
	layers.LayerTypeVXLAN,
	"Virtual Extensible LAN is a network virtualization technology that attempts to address the scalability problems associated with large cloud computing deployments",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if vx, ok := layer.(*layers.VXLAN); ok {
			return &types.VXLAN{
				Timestamp:        timestamp,
				ValidIDFlag:      vx.ValidIDFlag,
				VNI:              vx.VNI,
				GBPExtension:     vx.GBPExtension,
				GBPDontLearn:     vx.GBPDontLearn,
				GBPApplied:       vx.GBPApplied,
				GBPGroupPolicyID: int32(vx.GBPGroupPolicyID),
			}
		}

		return nil
	},
)
