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

var pppoeDecoder = newGoPacketDecoder(
	types.Type_NC_PPPoE,
	layers.LayerTypePPPoE,
	"PPPoE (Point-to-Point Protocol over Ethernet) encapsulates PPP frames inside Ethernet frames, commonly used for DSL connections",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if pppoe, ok := layer.(*layers.PPPoE); ok {
			// PPPoE code values from RFC 2516
			const (
				PPPoECodePADI = 0x09 // Active Discovery Initiation
				PPPoECodePADO = 0x07 // Active Discovery Offer
				PPPoECodePADR = 0x19 // Active Discovery Request
				PPPoECodePADS = 0x65 // Active Discovery Session-confirmation
				PPPoECodePADT = 0xa7 // Active Discovery Terminate
			)

			code := uint8(pppoe.Code)
			isDiscovery := code == PPPoECodePADI || code == PPPoECodePADO ||
				code == PPPoECodePADR || code == PPPoECodePADS

			return &types.PPPoE{
				Timestamp:            timestamp,
				Version:              int32(pppoe.Version),
				Type:                 int32(pppoe.Type),
				Code:                 int32(pppoe.Code),
				CodeName:             pppoe.Code.String(),
				SessionId:            int32(pppoe.SessionId),
				Length:               int32(pppoe.Length),
				IsDiscovery:          isDiscovery,
				IsSessionTermination: code == PPPoECodePADT,
				IsSessionEstablished: code == PPPoECodePADS,
			}
		}

		return nil
	},
)
