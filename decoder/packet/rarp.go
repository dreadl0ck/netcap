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
	"encoding/binary"
	"net"

	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/dreadl0ck/netcap/types"
)

var rarpOperationNames = map[uint16]string{
	3: "RARP Request",
	4: "RARP Reply",
}

var rarpDecoder = newPacketDecoder(
	types.Type_NC_RARP,
	"RARP",
	"Reverse Address Resolution Protocol maps hardware addresses to IP addresses",
	nil,
	func(p gopacket.Packet) proto.Message {
		// Check for EtherType 0x8035 (RARP)
		ethLayer := p.Layer(layers.LayerTypeEthernet)
		if ethLayer == nil {
			return nil
		}

		eth, ok := ethLayer.(*layers.Ethernet)
		if !ok || eth.EthernetType != 0x8035 {
			return nil
		}

		// RARP has the same wire format as ARP
		payload := eth.Payload
		if len(payload) < 28 { // Minimum ARP/RARP packet size for IPv4
			return nil
		}

		hwType := binary.BigEndian.Uint16(payload[0:2])
		protoType := binary.BigEndian.Uint16(payload[2:4])
		hwSize := payload[4]
		protoSize := payload[5]
		operation := binary.BigEndian.Uint16(payload[6:8])

		// Only handle RARP operations (3=request, 4=reply)
		if operation != 3 && operation != 4 {
			return nil
		}

		opName := rarpOperationNames[operation]

		// Extract addresses (assuming standard lengths)
		var srcHw, dstHw, srcProto, dstProto string
		offset := 8
		if int(hwSize)*2+int(protoSize)*2+offset <= len(payload) {
			srcHw = net.HardwareAddr(payload[offset : offset+int(hwSize)]).String()
			offset += int(hwSize)
			srcProto = net.IP(payload[offset : offset+int(protoSize)]).String()
			offset += int(protoSize)
			dstHw = net.HardwareAddr(payload[offset : offset+int(hwSize)]).String()
			offset += int(hwSize)
			dstProto = net.IP(payload[offset : offset+int(protoSize)]).String()
		}

		return &types.RARP{
			Timestamp:          p.Metadata().Timestamp.UnixNano(),
			AddrType:           int32(hwType),
			Protocol:           int32(protoType),
			HwAddressSize:      int32(hwSize),
			ProtocolAddressSize: int32(protoSize),
			Operation:          int32(operation),
			OperationName:      opName,
			SrcHwAddress:       srcHw,
			SrcProtocolAddress: srcProto,
			DstHwAddress:       dstHw,
			DstProtocolAddress: dstProto,
		}
	},
	nil,
)
