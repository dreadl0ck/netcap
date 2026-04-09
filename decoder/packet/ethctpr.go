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

var ethernetCTPReplyDecoder = newPacketDecoder(
	types.Type_NC_EthernetCTPReply,
	"EthernetCTPReply",
	"Ethernet Configuration Testing Protocol Reply message, indicates a loopback response",
	nil,
	func(p gopacket.Packet) proto.Message {
		// Get the EthernetCTPReply layer
		layer := p.Layer(layers.LayerTypeEthernetCTPReply)
		if layer == nil {
			return nil
		}

		ethctpr, ok := layer.(*layers.EthernetCTPReply)
		if !ok {
			return nil
		}

		var (
			srcMAC, dstMAC string
			dataEntropy    float64
		)

		// Extract MAC addresses from Ethernet layer
		if ll := p.LinkLayer(); ll != nil {
			if len(ll.LinkFlow().Src().Raw()) > 0 {
				srcMAC = ll.LinkFlow().Src().String()
			}
			if len(ll.LinkFlow().Dst().Raw()) > 0 {
				dstMAC = ll.LinkFlow().Dst().String()
			}
		}

		// Calculate entropy of data payload if entropy calculation is enabled
		if conf.CalculateEntropy && len(ethctpr.Data) > 0 {
			dataEntropy = entropy(ethctpr.Data)
		}

		// Get function name
		functionName := ctpFunctionNames[uint16(ethctpr.Function)]
		if functionName == "" {
			functionName = "Unknown"
		}

		return &types.EthernetCTPReply{
			Timestamp:     p.Metadata().Timestamp.UnixNano(),
			Function:      int32(ethctpr.Function),
			ReceiptNumber: int32(ethctpr.ReceiptNumber),
			Data:          ethctpr.Data,
			SrcMAC:        srcMAC,
			DstMAC:        dstMAC,
			FunctionName:  functionName,
			DataSize:      int32(len(ethctpr.Data)),
			DataEntropy:   dataEntropy,
		}
	},
	nil,
)
