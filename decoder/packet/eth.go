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
	"net"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/types"
)

// ethernetTypeNames maps EtherType values to human-readable names
var ethernetTypeNames = map[layers.EthernetType]string{
	layers.EthernetTypeIPv4:            "IPv4",
	layers.EthernetTypeIPv6:            "IPv6",
	layers.EthernetTypeARP:             "ARP",
	layers.EthernetTypeDot1Q:           "802.1Q",
	layers.EthernetTypePPPoEDiscovery:  "PPPoE Discovery",
	layers.EthernetTypePPPoESession:    "PPPoE Session",
	layers.EthernetTypeLinkLayerDiscovery: "LLDP",
	layers.EthernetTypeEAPOL:           "EAPOL",
	layers.EthernetTypeMPLSUnicast:     "MPLS Unicast",
	layers.EthernetTypeMPLSMulticast:   "MPLS Multicast",
}

// broadcastMAC is ff:ff:ff:ff:ff:ff
var broadcastMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

var ethernetDecoder = newGoPacketDecoder(
	types.Type_NC_Ethernet,
	layers.LayerTypeEthernet,
	"Ethernet is a family of computer networking technologies commonly used in local area networks, metropolitan area networks and wide area networks",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if eth, ok := layer.(*layers.Ethernet); ok {
			var e float64
			if conf.CalculateEntropy {
				e = entropy(eth.Payload)
			}

			// Get EtherType name
			ethTypeName := ethernetTypeNames[eth.EthernetType]
			if ethTypeName == "" {
				ethTypeName = "Unknown"
			}

			// Check MAC address properties
			// Broadcast: ff:ff:ff:ff:ff:ff
			isBroadcast := eth.DstMAC.String() == broadcastMAC.String()

			// Multicast: first bit of first byte is 1 (01:xx:xx:xx:xx:xx pattern)
			isMulticast := len(eth.DstMAC) > 0 && (eth.DstMAC[0]&0x01) == 0x01 && !isBroadcast

			// Locally administered: second bit of first byte is 1
			isLocallyAdmin := len(eth.SrcMAC) > 0 && (eth.SrcMAC[0]&0x02) == 0x02

			return &types.Ethernet{
				Timestamp:            timestamp,
				SrcMAC:               eth.SrcMAC.String(),
				DstMAC:               eth.DstMAC.String(),
				EthernetType:         int32(eth.EthernetType),
				PayloadEntropy:       e,
				PayloadSize:          int32(len(eth.Payload)),
				EthernetTypeName:     ethTypeName,
				IsBroadcast:          isBroadcast,
				IsMulticast:          isMulticast,
				IsLocallyAdministered: isLocallyAdmin,
			}
		}

		return nil
	},
)
