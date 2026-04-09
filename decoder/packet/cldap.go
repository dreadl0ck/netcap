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
	"fmt"

	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/dreadl0ck/netcap/types"
)

// LDAP operation names
var ldapOperationNames = map[int]string{
	0:  "BindRequest",
	1:  "BindResponse",
	2:  "UnbindRequest",
	3:  "SearchRequest",
	4:  "SearchResultEntry",
	5:  "SearchResultDone",
	6:  "ModifyRequest",
	7:  "ModifyResponse",
	8:  "AddRequest",
	9:  "AddResponse",
	23: "ExtendedRequest",
	24: "ExtendedResponse",
}

// berReadLength reads a BER length value. Returns length and new offset, or -1 on error.
func berReadLength(data []byte, offset int) (length int, newOffset int) {
	if offset >= len(data) {
		return -1, -1
	}
	b := data[offset]
	offset++

	if b == 0x80 {
		// Indefinite length - scan for end-of-contents (0x00, 0x00)
		// Return -2 to indicate indefinite length
		return -2, offset
	}

	if b&0x80 == 0 {
		// Short form
		return int(b), offset
	}

	// Long form
	numBytes := int(b & 0x7F)
	if numBytes > 4 || offset+numBytes > len(data) {
		return -1, -1
	}

	length = 0
	for i := 0; i < numBytes; i++ {
		length = (length << 8) | int(data[offset])
		offset++
	}

	return length, offset
}

// berReadInteger reads a BER-encoded INTEGER value
func berReadInteger(data []byte, offset int) (value int, newOffset int) {
	if offset >= len(data) {
		return 0, -1
	}

	// Expect INTEGER tag (0x02)
	if data[offset] != 0x02 {
		return 0, -1
	}
	offset++

	length, offset := berReadLength(data, offset)
	if length < 0 || offset+length > len(data) {
		return 0, -1
	}

	// Parse integer value
	for i := 0; i < length; i++ {
		value = (value << 8) | int(data[offset+i])
	}

	return value, offset + length
}

// berReadOctetString reads a BER-encoded OCTET STRING or context-tagged string
func berReadOctetString(data []byte, offset int) (value string, newOffset int) {
	if offset >= len(data) {
		return "", -1
	}

	// Skip tag byte (could be OCTET STRING 0x04 or context-tagged)
	offset++
	if offset >= len(data) {
		return "", -1
	}

	length, offset := berReadLength(data, offset)
	if length < 0 || offset < 0 {
		return "", -1
	}

	if length == -2 {
		// Indefinite length - skip for now
		return "", offset
	}

	if offset+length > len(data) {
		return "", -1
	}

	return string(data[offset : offset+length]), offset + length
}

var cldapDecoder = newPacketDecoder(
	types.Type_NC_CLDAP,
	"CLDAP",
	"Connectionless LDAP on UDP port 389, commonly used for Active Directory domain discovery",
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

		// CLDAP uses UDP port 389
		if udp.DstPort != 389 && udp.SrcPort != 389 {
			return nil
		}

		payload := udp.Payload
		if len(payload) < 7 {
			return nil
		}

		// LDAP messages are ASN.1 BER encoded
		// Top-level: SEQUENCE { MessageID INTEGER, ProtocolOp CHOICE, ... }

		// Check for SEQUENCE tag (0x30)
		if payload[0] != 0x30 {
			return nil
		}

		// Read SEQUENCE length
		_, seqContentOffset := berReadLength(payload, 1)
		if seqContentOffset < 0 {
			return nil
		}

		// Read MessageID (INTEGER)
		messageID, offset := berReadInteger(payload, seqContentOffset)
		if offset < 0 {
			return nil
		}

		// Read Protocol Operation (context-specific tag)
		if offset >= len(payload) {
			return nil
		}
		opTag := payload[offset]
		opType := int(opTag & 0x1F) // Extract tag number from context-specific tag
		offset++
		if offset >= len(payload) {
			return nil
		}

		opLength, offset := berReadLength(payload, offset)
		if offset < 0 {
			return nil
		}

		opName := ldapOperationNames[opType]
		if opName == "" {
			opName = fmt.Sprintf("Unknown(%d)", opType)
		}

		var baseObject string

		// Parse SearchRequest (tag 3) - extract baseObject
		if opType == 3 && opLength != 0 && offset < len(payload) {
			baseObject, _ = berReadOctetString(payload, offset)
		}

		// Extract IP addresses
		var srcIP, dstIP string
		if nl := p.NetworkLayer(); nl != nil {
			srcIP = nl.NetworkFlow().Src().String()
			dstIP = nl.NetworkFlow().Dst().String()
		}

		return &types.CLDAP{
			Timestamp:  p.Metadata().Timestamp.UnixNano(),
			MessageID:  int32(messageID),
			Operation:  opName,
			BaseObject: baseObject,
			SrcIP:      srcIP,
			DstIP:      dstIP,
			SrcPort:    int32(udp.SrcPort),
			DstPort:    int32(udp.DstPort),
		}
	},
	nil,
)
