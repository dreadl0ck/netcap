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

var usbDecoder = newGoPacketDecoder(
	types.Type_NC_USB,
	layers.LayerTypeUSB,
	"Universal Serial Bus (USB) is an industry standard that establishes specifications for cables and connectors and protocols for connection, communication and power supply (interfacing) between computers, peripherals and other computers",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if usb, ok := layer.(*layers.USB); ok {
			var payload []byte
			if conf.IncludePayloads {
				payload = layer.LayerPayload()
			}

			return &types.USB{
				Timestamp:              timestamp,
				ID:                     usb.ID,
				EventType:              int32(usb.EventType),
				TransferType:           int32(usb.TransferType),
				Direction:              int32(usb.Direction),
				EndpointNumber:         int32(usb.EndpointNumber),
				DeviceAddress:          int32(usb.DeviceAddress),
				BusID:                  int32(usb.BusID),
				TimestampSec:           usb.TimestampSec,
				TimestampUsec:          usb.TimestampUsec,
				Setup:                  usb.Setup,
				Data:                   usb.Data,
				Status:                 usb.Status,
				UrbLength:              usb.UrbLength,
				UrbDataLength:          usb.UrbDataLength,
				UrbInterval:            usb.UrbInterval,
				UrbStartFrame:          usb.UrbStartFrame,
				UrbCopyOfTransferFlags: usb.UrbCopyOfTransferFlags,
				IsoNumDesc:             usb.IsoNumDesc,
				Payload:                payload,
			}
		}

		return nil
	},
)
