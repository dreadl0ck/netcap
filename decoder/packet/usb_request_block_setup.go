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

var usbRequestBlockSetupDecoder = newGoPacketDecoder(
	types.Type_NC_USBRequestBlockSetup,
	layers.LayerTypeUSBRequestBlockSetup,
	"Universal Serial Bus (USB) is an industry standard that establishes specifications for cables and connectors and protocols for connection, communication and power supply (interfacing) between computers, peripherals and other computers",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if usbR, ok := layer.(*layers.USBRequestBlockSetup); ok {
			return &types.USBRequestBlockSetup{
				Timestamp:   timestamp,
				RequestType: int32(usbR.RequestType),
				Request:     int32(usbR.Request),
				Value:       int32(usbR.Value),
				Index:       int32(usbR.Index),
				Length:      int32(usbR.Length),
			}
		}

		return nil
	},
)
