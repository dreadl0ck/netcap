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

var pppDecoder = newGoPacketDecoder(
	types.Type_NC_PPP,
	layers.LayerTypePPP,
	"PPP (Point-to-Point Protocol) is a data link layer protocol used to establish direct connections between two nodes",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if ppp, ok := layer.(*layers.PPP); ok {
			// PPP Type values
			const (
				PPPTypeIPv4   = 0x0021
				PPPTypeIPv6   = 0x0057
				PPPTypeLCP    = 0xc021 // Link Control Protocol
				PPPTypePAP    = 0xc023 // Password Authentication Protocol
				PPPTypeCHAP   = 0xc223 // Challenge Handshake Authentication Protocol
				PPPTypeIPCP   = 0x8021 // IP Control Protocol
				PPPTypeIPv6CP = 0x8057 // IPv6 Control Protocol
			)

			pppType := uint16(ppp.PPPType)
			isControlProtocol := pppType == PPPTypeLCP || pppType == PPPTypePAP ||
				pppType == PPPTypeCHAP || pppType == PPPTypeIPCP || pppType == PPPTypeIPv6CP
			isAuthentication := pppType == PPPTypePAP || pppType == PPPTypeCHAP

			return &types.PPP{
				Timestamp:         timestamp,
				PPPType:           int32(ppp.PPPType),
				PPPTypeName:       ppp.PPPType.String(),
				HasPPTPHeader:     ppp.HasPPTPHeader,
				IsControlProtocol: isControlProtocol,
				IsAuthentication:  isAuthentication,
				IsIPv4:            pppType == PPPTypeIPv4,
				IsIPv6:            pppType == PPPTypeIPv6,
			}
		}

		return nil
	},
)
