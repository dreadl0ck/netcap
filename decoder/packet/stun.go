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
	"fmt"
	"net"

	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/dreadl0ck/netcap/types"
)

const stunMagicCookie = 0x2112A442

// STUN attribute types
const (
	stunAttrMappedAddress    = 0x0001
	stunAttrUsername          = 0x0006
	stunAttrMessageIntegrity = 0x0008
	stunAttrErrorCode        = 0x0009
	stunAttrXORMappedAddress = 0x0020
	stunAttrSoftware         = 0x8022
	stunAttrFingerprint      = 0x8028
)

var stunAttrNames = map[uint16]string{
	stunAttrMappedAddress:    "MAPPED-ADDRESS",
	stunAttrUsername:          "USERNAME",
	stunAttrMessageIntegrity: "MESSAGE-INTEGRITY",
	stunAttrErrorCode:        "ERROR-CODE",
	stunAttrXORMappedAddress: "XOR-MAPPED-ADDRESS",
	stunAttrSoftware:         "SOFTWARE",
	stunAttrFingerprint:      "FINGERPRINT",
}

// STUN message classes
var stunMessageClasses = map[uint16]string{
	0x0000: "Request",
	0x0010: "Indication",
	0x0100: "SuccessResponse",
	0x0110: "ErrorResponse",
}

// STUN methods
var stunMethods = map[uint16]string{
	0x001: "Binding",
	0x003: "Allocate",
	0x004: "Refresh",
	0x006: "Send",
	0x007: "Data",
	0x008: "CreatePermission",
	0x009: "ChannelBind",
}

var stunDecoder = newPacketDecoder(
	types.Type_NC_STUN,
	"STUN",
	"Session Traversal Utilities for NAT enables NAT traversal for VoIP and WebRTC applications",
	nil,
	func(p gopacket.Packet) proto.Message {
		udpLayer := p.Layer(layers.LayerTypeUDP)
		if udpLayer == nil {
			return nil
		}

		udp, ok := udpLayer.(*layers.UDP)
		if !ok {
			return nil
		}

		payload := udp.Payload
		if len(payload) < 20 {
			return nil
		}

		// First two bits must be zero (RFC 5389)
		if payload[0]&0xC0 != 0 {
			return nil
		}

		// Check magic cookie at bytes 4-8
		cookie := binary.BigEndian.Uint32(payload[4:8])
		isRFC5389 := cookie == stunMagicCookie
		if !isRFC5389 {
			return nil
		}

		msgType := binary.BigEndian.Uint16(payload[0:2])
		msgLen := binary.BigEndian.Uint16(payload[2:4])
		transactionID := payload[8:20]

		// Validate message length
		if int(msgLen)+20 > len(payload) {
			return nil
		}

		// Decode message class (RFC 5389: C0=bit4, C1=bit8)
		var classStr string
		switch {
		case msgType&0x0110 == 0x0000:
			classStr = "Request"
		case msgType&0x0110 == 0x0010:
			classStr = "Indication"
		case msgType&0x0110 == 0x0100:
			classStr = "SuccessResponse"
		case msgType&0x0110 == 0x0110:
			classStr = "ErrorResponse"
		}

		method := (msgType & 0x000F) | ((msgType & 0x00E0) >> 1) | ((msgType & 0x3E00) >> 2)
		methodStr := stunMethods[method]
		if methodStr == "" {
			methodStr = fmt.Sprintf("Unknown(0x%03x)", method)
		}

		// Parse attributes
		var (
			mappedAddr string
			attrs      []*types.STUNAttribute
		)
		offset := 20
		end := 20 + int(msgLen)
		for offset+4 <= end {
			attrType := binary.BigEndian.Uint16(payload[offset : offset+2])
			attrLen := binary.BigEndian.Uint16(payload[offset+2 : offset+4])
			offset += 4

			if offset+int(attrLen) > end {
				break
			}

			attrValue := payload[offset : offset+int(attrLen)]
			attrName := stunAttrNames[attrType]
			if attrName == "" {
				attrName = fmt.Sprintf("0x%04x", attrType)
			}

			var decoded string

			// Decode MAPPED-ADDRESS and XOR-MAPPED-ADDRESS
			if attrType == stunAttrMappedAddress && len(attrValue) >= 8 {
				family := attrValue[1]
				port := binary.BigEndian.Uint16(attrValue[2:4])
				if family == 0x01 && len(attrValue) >= 8 { // IPv4
					ip := net.IP(attrValue[4:8])
					decoded = fmt.Sprintf("%s:%d", ip, port)
					mappedAddr = decoded
				}
			} else if attrType == stunAttrXORMappedAddress && len(attrValue) >= 8 {
				family := attrValue[1]
				port := binary.BigEndian.Uint16(attrValue[2:4]) ^ uint16(stunMagicCookie>>16)
				if family == 0x01 && len(attrValue) >= 8 { // IPv4
					xoredIP := binary.BigEndian.Uint32(attrValue[4:8])
					ip := make(net.IP, 4)
					binary.BigEndian.PutUint32(ip, xoredIP^stunMagicCookie)
					decoded = fmt.Sprintf("%s:%d", ip, port)
					mappedAddr = decoded
				}
			} else if attrType == stunAttrSoftware || attrType == stunAttrUsername {
				decoded = string(attrValue)
			}

			attrs = append(attrs, &types.STUNAttribute{
				Type:         int32(attrType),
				TypeName:     attrName,
				Length:       int32(attrLen),
				Value:        attrValue,
				DecodedValue: decoded,
			})

			// Pad to 4-byte boundary
			offset += int(attrLen)
			if pad := int(attrLen) % 4; pad != 0 {
				offset += 4 - pad
			}
		}

		// Extract IP addresses
		var srcIP, dstIP string
		if nl := p.NetworkLayer(); nl != nil {
			srcIP = nl.NetworkFlow().Src().String()
			dstIP = nl.NetworkFlow().Dst().String()
		}

		return &types.STUN{
			Timestamp:     p.Metadata().Timestamp.UnixNano(),
			MessageType:   int32(msgType),
			MessageLength: int32(msgLen),
			TransactionID: transactionID,
			MessageClass:  classStr,
			Method:        methodStr,
			MappedAddress: mappedAddr,
			SrcIP:         srcIP,
			DstIP:         dstIP,
			SrcPort:       int32(udp.SrcPort),
			DstPort:       int32(udp.DstPort),
			IsRFC5389:     isRFC5389,
			Attributes:    attrs,
		}
	},
	nil,
)
