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
	"encoding/binary"
	"net"

	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/dreadl0ck/netcap/types"
)

var radiusDecoder = newGoPacketDecoder(
	types.Type_NC_RADIUS,
	layers.LayerTypeRADIUS,
	"Remote Authentication Dial-In User Service (RADIUS) is a networking protocol providing centralized AAA management",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if radius, ok := layer.(*layers.RADIUS); ok {
			// Parse attributes
			var (
				attrs         []*types.RADIUSAttribute
				username      string
				nasIPAddress  string
				nasIdentifier string
				serviceType   int32
				acctSessionID string
				acctStatusType int32
				replyMessage  string
			)

			for _, attr := range radius.Attributes {
				ra := &types.RADIUSAttribute{
					Type:         int32(attr.Type),
					TypeName:     attr.Type.String(),
					Length:       int32(attr.Length),
					Value:        attr.Value,
					DecodedValue: decodeRADIUSAttributeValue(attr),
				}
				attrs = append(attrs, ra)

				// Extract commonly used attributes
				switch attr.Type {
				case layers.RADIUSAttributeTypeUserName:
					username = string(attr.Value)
				case layers.RADIUSAttributeTypeNASIPAddress:
					if len(attr.Value) == 4 {
						nasIPAddress = net.IP(attr.Value).String()
					}
				case layers.RADIUSAttributeTypeNASIdentifier:
					nasIdentifier = string(attr.Value)
			case layers.RADIUSAttributeTypeServiceType:
				if len(attr.Value) >= 4 {
					// RFC 2865: Integer attributes are 4 bytes in network byte order
					serviceType = int32(binary.BigEndian.Uint32(attr.Value))
				}
			case layers.RADIUSAttributeTypeAcctSessionId:
				acctSessionID = string(attr.Value)
			case layers.RADIUSAttributeTypeAcctStatusType:
				if len(attr.Value) >= 4 {
					// RFC 2866: Integer attributes are 4 bytes in network byte order
					acctStatusType = int32(binary.BigEndian.Uint32(attr.Value))
				}
				case layers.RADIUSAttributeTypeReplyMessage:
					replyMessage = string(attr.Value)
				}
			}

			// Determine if request or response
			isRequest := radius.Code == layers.RADIUSCodeAccessRequest ||
				radius.Code == layers.RADIUSCodeAccountingRequest

			// Determine auth success
			authSuccess := radius.Code == layers.RADIUSCodeAccessAccept

			return &types.RADIUS{
				Timestamp:      timestamp,
				Code:           int32(radius.Code),
				CodeName:       radius.Code.String(),
				Identifier:     int32(radius.Identifier),
				Length:         int32(radius.Length),
				Authenticator:  radius.Authenticator[:],
				Username:       username,
				NASIPAddress:   nasIPAddress,
				NASIdentifier:  nasIdentifier,
				ServiceType:    serviceType,
				ServiceTypeName: getServiceTypeName(serviceType),
				AcctSessionID:  acctSessionID,
				AcctStatusType: acctStatusType,
				AcctStatusTypeName: getAcctStatusTypeName(acctStatusType),
				ReplyMessage:   replyMessage,
				Attributes:     attrs,
				IsRequest:      isRequest,
				AuthSuccess:    authSuccess,
			}
		}

		return nil
	},
)

// decodeRADIUSAttributeValue converts RADIUS attribute value to human-readable string
func decodeRADIUSAttributeValue(attr layers.RADIUSAttribute) string {
	switch attr.Type {
	case layers.RADIUSAttributeTypeUserName,
		layers.RADIUSAttributeTypeNASIdentifier,
		layers.RADIUSAttributeTypeReplyMessage,
		layers.RADIUSAttributeTypeCalledStationId,
		layers.RADIUSAttributeTypeCallingStationId,
		layers.RADIUSAttributeTypeAcctSessionId:
		return string(attr.Value)
	case layers.RADIUSAttributeTypeNASIPAddress,
		layers.RADIUSAttributeTypeFramedIPAddress:
		if len(attr.Value) == 4 {
			return net.IP(attr.Value).String()
		}
	}
	return ""
}

// getServiceTypeName returns human-readable service type name
func getServiceTypeName(serviceType int32) string {
	switch serviceType {
	case 1:
		return "Login"
	case 2:
		return "Framed"
	case 3:
		return "Callback-Login"
	case 4:
		return "Callback-Framed"
	case 5:
		return "Outbound"
	case 6:
		return "Administrative"
	case 7:
		return "NAS-Prompt"
	case 8:
		return "Authenticate-Only"
	case 9:
		return "Callback-NAS-Prompt"
	case 10:
		return "Call-Check"
	case 11:
		return "Callback-Administrative"
	default:
		return ""
	}
}

// getAcctStatusTypeName returns human-readable accounting status type name
func getAcctStatusTypeName(acctStatusType int32) string {
	switch acctStatusType {
	case 1:
		return "Start"
	case 2:
		return "Stop"
	case 3:
		return "Interim-Update"
	case 7:
		return "Accounting-On"
	case 8:
		return "Accounting-Off"
	case 9:
		return "Tunnel-Start"
	case 10:
		return "Tunnel-Stop"
	case 11:
		return "Tunnel-Reject"
	case 12:
		return "Tunnel-Link-Start"
	case 13:
		return "Tunnel-Link-Stop"
	case 14:
		return "Tunnel-Link-Reject"
	case 15:
		return "Failed"
	default:
		return ""
	}
}

