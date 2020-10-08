/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017-2020 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package packet

import (
	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/gopacket/layers"
	"github.com/gogo/protobuf/proto"

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
