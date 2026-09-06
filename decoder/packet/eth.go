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
	"net"

	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket/layers"

	"github.com/dreadl0ck/netcap/types"
)

// ethernetTypeNames maps EtherType values to human-readable names
var ethernetTypeNames = map[layers.EthernetType]string{
	layers.EthernetTypeIPv4:               "IPv4",
	layers.EthernetTypeIPv6:               "IPv6",
	layers.EthernetTypeARP:                "ARP",
	layers.EthernetTypeDot1Q:              "802.1Q",
	layers.EthernetTypePPPoEDiscovery:     "PPPoE Discovery",
	layers.EthernetTypePPPoESession:       "PPPoE Session",
	layers.EthernetTypeLinkLayerDiscovery: "LLDP",
	layers.EthernetTypeEAPOL:              "EAPOL",
	layers.EthernetTypeMPLSUnicast:        "MPLS Unicast",
	layers.EthernetTypeMPLSMulticast:      "MPLS Multicast",
}

// broadcastMAC is ff:ff:ff:ff:ff:ff
var broadcastMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

var ethernetDecoder = newGoPacketDecoder(
	types.Type_NC_Ethernet,
	layers.LayerTypeEthernet,
	"Ethernet is a family of computer networking technologies commonly used in local area networks, metropolitan area networks and wide area networks",
	typedLayerHandler(decodeEthernet),
)

func decodeEthernet(eth *layers.Ethernet, timestamp int64) proto.Message {
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
		Timestamp:             timestamp,
		SrcMAC:                eth.SrcMAC.String(),
		DstMAC:                eth.DstMAC.String(),
		EthernetType:          int32(eth.EthernetType),
		PayloadEntropy:        e,
		PayloadSize:           int32(len(eth.Payload)),
		EthernetTypeName:      ethTypeName,
		IsBroadcast:           isBroadcast,
		IsMulticast:           isMulticast,
		IsLocallyAdministered: isLocallyAdmin,
	}
}
