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
	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/dreadl0ck/netcap/types"
)

var gtpDecoder = newGoPacketDecoder(
	types.Type_NC_GTP,
	layers.LayerTypeGTPv1U,
	"GPRS Tunneling Protocol (GTP) is used in mobile networks for tunneling user data and signaling",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if gtp, ok := layer.(*layers.GTPv1U); ok {
			// Parse extension headers
			var infoElements []*types.GTPInfoElement
			for _, eh := range gtp.GTPExtensionHeaders {
				ie := &types.GTPInfoElement{
					Type:     int32(eh.Type),
					TypeName: getGTPExtensionHeaderTypeName(eh.Type),
					Length:   int32(len(eh.Content)),
					Value:    eh.Content,
				}
				infoElements = append(infoElements, ie)
			}

		return &types.GTP{
			Timestamp:       timestamp,
			Version:         int32(gtp.Version),
			ProtocolType:    gtp.ProtocolType == 1, // 1 = GTP, 0 = GTP'
			MessageType:     int32(gtp.MessageType),
			MessageTypeName: getGTPv1UMessageTypeName(gtp.MessageType),
			Length:          int32(gtp.MessageLength),
			TEID:            gtp.TEID,
			SequenceNumber:  int32(gtp.SequenceNumber),
			NPDUNumber:      int32(gtp.NPDU),
			IsSignaling:     false, // GTPv1U is user plane, not signaling
			InfoElements:    infoElements,
		}
		}

		return nil
	},
)

// getGTPv1UMessageTypeName returns human-readable message type name for GTPv1-U
func getGTPv1UMessageTypeName(msgType uint8) string {
	switch msgType {
	case 1:
		return "Echo Request"
	case 2:
		return "Echo Response"
	case 26:
		return "Error Indication"
	case 31:
		return "Supported Extension Headers Notification"
	case 254:
		return "End Marker"
	case 255:
		return "G-PDU"
	default:
		return "Unknown"
	}
}

// getGTPExtensionHeaderTypeName returns human-readable extension header type name
func getGTPExtensionHeaderTypeName(ehType uint8) string {
	switch ehType {
	case 0:
		return "No more extension headers"
	case 1:
		return "MBMS support indication"
	case 2:
		return "MS Info Change Reporting support indication"
	case 32:
		return "PDCP PDU Number"
	case 64:
		return "Suspend Request"
	case 65:
		return "Suspend Response"
	case 130:
		return "RAN Container"
	case 131:
		return "Xw RAN Container"
	case 132:
		return "NR RAN Container"
	case 133:
		return "PDU Session Container"
	case 193:
		return "PDCP PDU Number (extended)"
	case 194:
		return "NR RAN Container (extended)"
	default:
		return "Unknown"
	}
}

