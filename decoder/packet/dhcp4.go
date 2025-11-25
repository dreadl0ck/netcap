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
	"strconv"
	"strings"

	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/dreadl0ck/netcap/types"
)

// dhcpv4MessageTypeNames maps DHCP message types to names
var dhcpv4MessageTypeNames = map[layers.DHCPMsgType]string{
	layers.DHCPMsgTypeDiscover: "DISCOVER",
	layers.DHCPMsgTypeOffer:    "OFFER",
	layers.DHCPMsgTypeRequest:  "REQUEST",
	layers.DHCPMsgTypeDecline:  "DECLINE",
	layers.DHCPMsgTypeAck:      "ACK",
	layers.DHCPMsgTypeNak:      "NAK",
	layers.DHCPMsgTypeRelease:  "RELEASE",
	layers.DHCPMsgTypeInform:   "INFORM",
}

// DHCP option types
const (
	dhcpOptHostname        = 12
	dhcpOptVendorClass     = 60
	dhcpOptServerID        = 54
	dhcpOptMessageType     = 53
	dhcpOptLeaseTime       = 51
)

var dhcpv4Decoder = newGoPacketDecoder(
	types.Type_NC_DHCPv4,
	layers.LayerTypeDHCPv4,
	"The Dynamic Host Configuration Protocol (DHCP) is a network management protocol used on Internet Protocol networks whereby a DHCP server dynamically assigns an IP address and other network configuration parameters to each device on a network so they can communicate with other IP networks",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if dhcp4, ok := layer.(*layers.DHCPv4); ok {

			var (
				opts             = make([]*types.DHCPOption, 0, len(dhcp4.Options))
				fp               strings.Builder
				length           = len(dhcp4.Options) - 1
				messageType      string
				messageTypeCode  int32
				leaseTime        uint32
				serverIdentifier string
				hostname         string
				vendorClass      string
			)

			for i, o := range dhcp4.Options {
				opts = append(opts, &types.DHCPOption{
					Data:   string(o.Data),
					Length: int32(o.Length),
					Type:   int32(o.Type),
				})
				fp.WriteString(strconv.Itoa(int(o.Type)))
				if i != length {
					fp.WriteString(",")
				}

				// Extract security-relevant DHCP options
				switch o.Type {
				case dhcpOptMessageType:
					if len(o.Data) >= 1 {
						msgType := layers.DHCPMsgType(o.Data[0])
						messageTypeCode = int32(msgType)
						messageType = dhcpv4MessageTypeNames[msgType]
						if messageType == "" {
							messageType = "UNKNOWN"
						}
					}
				case dhcpOptLeaseTime:
					if len(o.Data) >= 4 {
						leaseTime = uint32(o.Data[0])<<24 | uint32(o.Data[1])<<16 | uint32(o.Data[2])<<8 | uint32(o.Data[3])
					}
				case dhcpOptServerID:
					if len(o.Data) >= 4 {
						serverIdentifier = parseIPv4(o.Data[:4])
					}
				case dhcpOptHostname:
					hostname = string(o.Data)
				case dhcpOptVendorClass:
					vendorClass = string(o.Data)
				}
			}

			return &types.DHCPv4{
				Timestamp:        timestamp,
				Operation:        int32(dhcp4.Operation),
				HardwareType:     int32(dhcp4.HardwareType),
				HardwareLen:      int32(dhcp4.HardwareLen),
				RelayHops:        int32(dhcp4.RelayHops),
				Xid:              dhcp4.Xid,
				Secs:             int32(dhcp4.Secs),
				Flags:            int32(dhcp4.Flags),
				ClientIP:         dhcp4.ClientIP.String(),
				YourClientIP:     dhcp4.YourClientIP.String(),
				NextServerIP:     dhcp4.NextServerIP.String(),
				RelayAgentIP:     dhcp4.RelayAgentIP.String(),
				ClientHWAddr:     dhcp4.ClientHWAddr.String(),
				ServerName:       dhcp4.ServerName,
				File:             dhcp4.File,
				Options:          opts,
				Fingerprint:      fp.String(),
				MessageType:      messageType,
				MessageTypeCode:  messageTypeCode,
				LeaseTime:        leaseTime,
				ServerIdentifier: serverIdentifier,
				Hostname:         hostname,
				VendorClass:      vendorClass,
			}
		}

		return nil
	},
)
