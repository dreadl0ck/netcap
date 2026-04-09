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

var dot1QDecoder = newGoPacketDecoder(
	types.Type_NC_Dot1Q,
	layers.LayerTypeDot1Q,
	"IEEE 802.11 is part of the IEEE 802 set of local area network protocols, and specifies the set of media access control and physical layer protocols for implementing wireless local area network Wi-Fi",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if dot1q, ok := layer.(*layers.Dot1Q); ok {
			return &types.Dot1Q{
				Timestamp:      timestamp,
				Priority:       int32(dot1q.Priority),
				DropEligible:   dot1q.DropEligible,
				VLANIdentifier: int32(dot1q.VLANIdentifier),
				Type:           int32(dot1q.Type),
			}
		}

		return nil
	},
)
