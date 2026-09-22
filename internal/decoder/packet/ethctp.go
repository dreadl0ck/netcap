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
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/dreadl0ck/netcap/types"
)

// CTP function codes as defined in the Xerox Ethernet II specification
const (
	EthernetCTPFunctionReply       = 1
	EthernetCTPFunctionForwardData = 2
)

// ctpFunctionNames maps CTP function codes to human-readable names
var ctpFunctionNames = map[uint16]string{
	EthernetCTPFunctionReply:       "Reply",
	EthernetCTPFunctionForwardData: "ForwardData",
}

// loopbackAssistantMAC is the CTP loopback assistance multicast address (CF:00:00:00:00:00)
// Stations implementing loopback assistant functionality listen on this address
var loopbackAssistantMAC = net.HardwareAddr{0xcf, 0x00, 0x00, 0x00, 0x00, 0x00}

var ethernetCTPDecoder = newPacketDecoder(
	types.Type_NC_EthernetCTP,
	"EthernetCTP",
	"Ethernet Configuration Testing Protocol is a diagnostic protocol included in the Xerox Ethernet II specification for loopback testing",
	nil,
	func(p gopacket.Packet) proto.Message {
		// Get the EthernetCTP layer
		layer := p.Layer(layers.LayerTypeEthernetCTP)
		if layer == nil {
			return nil
		}

		ethctp, ok := layer.(*layers.EthernetCTP)
		if !ok {
			return nil
		}

		var (
			srcMAC, dstMAC      string
			isBroadcast         bool
			isMulticast         bool
			isLoopbackAssistant bool
			numHops             int32
			forwardAddresses    []string
			functionCode        int32
			functionName        string
			payloadSize         int32
		)

		// Extract MAC addresses from Ethernet layer
		if ll := p.LinkLayer(); ll != nil {
			if len(ll.LinkFlow().Src().Raw()) > 0 {
				srcMAC = ll.LinkFlow().Src().String()
			}
			if len(ll.LinkFlow().Dst().Raw()) > 0 {
				dstMAC = ll.LinkFlow().Dst().String()
			}

			// Check if destination is broadcast (ff:ff:ff:ff:ff:ff)
			if eth, ok := p.Layer(layers.LayerTypeEthernet).(*layers.Ethernet); ok {
				isBroadcast = eth.DstMAC.String() == broadcastMAC.String()

				// Multicast: first bit of first byte is 1 (01:xx:xx:xx:xx:xx pattern)
				isMulticast = len(eth.DstMAC) > 0 && (eth.DstMAC[0]&0x01) == 0x01 && !isBroadcast

				// Check for loopback assistant multicast address (cf:00:00:00:00:00)
				isLoopbackAssistant = eth.DstMAC.String() == loopbackAssistantMAC.String()
			}
		}

		// Calculate payload size from CTP layer
		if ethctp.BaseLayer.Payload != nil {
			payloadSize = int32(len(ethctp.BaseLayer.Payload))
		}

		// Count ForwardData layers and extract forwarding addresses
		for _, l := range p.Layers() {
			if forwardData, ok := l.(*layers.EthernetCTPForwardData); ok {
				numHops++
				if forwardData.ForwardAddress != nil {
					forwardAddresses = append(forwardAddresses, net.HardwareAddr(forwardData.ForwardAddress).String())
				}
				// Get function code from first ForwardData layer
				if numHops == 1 {
					functionCode = int32(forwardData.Function)
					functionName = ctpFunctionNames[uint16(forwardData.Function)]
					if functionName == "" {
						functionName = "Unknown"
					}
				}
			}
		}

		// If no ForwardData layers, check for Reply layer to get function code
		if numHops == 0 {
			if replyLayer := p.Layer(layers.LayerTypeEthernetCTPReply); replyLayer != nil {
				if reply, ok := replyLayer.(*layers.EthernetCTPReply); ok {
					functionCode = int32(reply.Function)
					functionName = ctpFunctionNames[uint16(reply.Function)]
					if functionName == "" {
						functionName = "Unknown"
					}
				}
			}
		}

		return &types.EthernetCTP{
			Timestamp:           p.Metadata().Timestamp.UnixNano(),
			SkipCount:           int32(ethctp.SkipCount),
			SrcMAC:              srcMAC,
			DstMAC:              dstMAC,
			IsBroadcast:         isBroadcast,
			IsMulticast:         isMulticast,
			IsLoopbackAssistant: isLoopbackAssistant,
			NumHops:             numHops,
			ForwardAddresses:    forwardAddresses,
			FunctionCode:        functionCode,
			FunctionName:        functionName,
			PayloadSize:         payloadSize,
		}
	},
	nil,
)
