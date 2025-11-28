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

// getRMCPClassName returns a human-readable name for the RMCP class
func getRMCPClassName(class layers.RMCPClass) string {
	switch class {
	case 0x06:
		return "ASF"
	case 0x07:
		return "IPMI"
	case 0x08:
		return "OEM"
	default:
		return "Unknown"
	}
}

// RMCP class constants
const (
	RMCPClassASF  = 0x06
	RMCPClassIPMI = 0x07
)

var rmcpDecoder = newGoPacketDecoder(
	types.Type_NC_RMCP,
	layers.LayerTypeRMCP,
	"RMCP (Remote Management Control Protocol) is used for remote management of devices, commonly in IPMI/BMC systems",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if rmcp, ok := layer.(*layers.RMCP); ok {
			class := uint8(rmcp.Class)
			return &types.RMCP{
				Timestamp:     timestamp,
				Version:       int32(rmcp.Version),
				Sequence:      int32(rmcp.Sequence),
				Ack:           rmcp.Ack,
				Class:         int32(rmcp.Class),
				ClassName:     getRMCPClassName(rmcp.Class),
				IsIPMI:        class == RMCPClassIPMI,
				IsASF:         class == RMCPClassASF,
				NoAckRequired: rmcp.Sequence == 255,
			}
		}

		return nil
	},
)
