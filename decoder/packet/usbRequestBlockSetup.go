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
