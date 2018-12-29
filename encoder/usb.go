/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package encoder

import (
	"github.com/dreadl0ck/netcap/types"
	"github.com/golang/protobuf/proto"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var usbEncoder = CreateLayerEncoder(types.Type_NC_USB, layers.LayerTypeUSB, func(layer gopacket.Layer, timestamp string) proto.Message {
	if usb, ok := layer.(*layers.USB); ok {
		return &types.USB{
			Timestamp:              timestamp,
			ID:                     uint64(usb.ID),
			EventType:              int32(usb.EventType),
			TransferType:           int32(usb.TransferType),
			Direction:              int32(usb.Direction),
			EndpointNumber:         int32(usb.EndpointNumber),
			DeviceAddress:          int32(usb.DeviceAddress),
			BusID:                  int32(usb.BusID),
			TimestampSec:           int64(usb.TimestampSec),
			TimestampUsec:          int32(usb.TimestampUsec),
			Setup:                  bool(usb.Setup),
			Data:                   bool(usb.Data),
			Status:                 int32(usb.Status),
			UrbLength:              uint32(usb.UrbLength),
			UrbDataLength:          uint32(usb.UrbDataLength),
			UrbInterval:            uint32(usb.UrbInterval),
			UrbStartFrame:          uint32(usb.UrbStartFrame),
			UrbCopyOfTransferFlags: uint32(usb.UrbCopyOfTransferFlags),
			IsoNumDesc:             uint32(usb.IsoNumDesc),
		}
	}
	return nil
})
