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
	"encoding/hex"
	"fmt"

	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/dreadl0ck/netcap/types"
)

// IS-IS NLPID (Network Layer Protocol Identifier)
const isisNLPID = 0x83

// IS-IS PDU type names
var isisPDUTypeNames = map[uint8]string{
	15: "L1 LAN Hello",
	16: "L2 LAN Hello",
	17: "P2P Hello",
	18: "L1 LSP",
	20: "L2 LSP",
	24: "L1 CSNP",
	25: "L2 CSNP",
	26: "L1 PSNP",
	27: "L2 PSNP",
}

var isisDecoder = newPacketDecoder(
	types.Type_NC_ISIS,
	"ISIS",
	"Intermediate System to Intermediate System is a routing protocol used in large service provider networks",
	nil,
	func(p gopacket.Packet) proto.Message {
		// IS-IS runs directly over Layer 2 using LLC with DSAP/SSAP = 0xFE
		llcLayer := p.Layer(layers.LayerTypeLLC)
		if llcLayer == nil {
			return nil
		}

		llc, ok := llcLayer.(*layers.LLC)
		if !ok {
			return nil
		}

		// IS-IS uses DSAP = 0xFE, SSAP = 0xFE
		if llc.DSAP != 0xFE || llc.SSAP != 0xFE {
			return nil
		}

		payload := llc.Payload
		if len(payload) < 8 {
			return nil
		}

		// Verify NLPID
		if payload[0] != isisNLPID {
			return nil
		}

		// IS-IS common header:
		// NLPID(1) + headerLength(1) + version(1) + IDLength(1) + PDUType(1) + version2(1) + reserved(1) + maxAreaAddr(1)
		pduType := payload[4] & 0x1F // lower 5 bits
		version := payload[2]
		pduLength := int(payload[1])

		pduTypeName := isisPDUTypeNames[pduType]
		if pduTypeName == "" {
			pduTypeName = fmt.Sprintf("Unknown(%d)", pduType)
		}

		var systemID string
		var holdingTime int32
		var circuitType int32
		var areaAddresses []string

		// Parse Hello PDUs (types 15, 16, 17)
		if (pduType == 15 || pduType == 16 || pduType == 17) && len(payload) >= 27 {
			// Hello header after common header (8 bytes):
			// CircuitType(1) + SourceID(6) + HoldingTime(2) + PDULength(2) + ...
			circuitType = int32(payload[8])
			if len(payload) >= 15 {
				systemID = hex.EncodeToString(payload[9:15])
			}
			if len(payload) >= 17 {
				holdingTime = int32(payload[15])<<8 | int32(payload[16])
			}

			// Parse TLVs for area addresses
			tlvOffset := 27 // Common header (8) + Hello specific (19)
			if pduType == 17 {
				tlvOffset = 20 // P2P Hello has shorter fixed header
			}
			areaAddresses = parseISISTLVs(payload, tlvOffset, pduLength)
		}

		// Parse LSP PDUs (types 18, 20)
		if (pduType == 18 || pduType == 20) && len(payload) >= 27 {
			// LSP header: PDULength(2) + RemainingLifetime(2) + LSPID(8) + SequenceNumber(4) + Checksum(2) + TypeBlock(1)
			if len(payload) >= 21 {
				systemID = hex.EncodeToString(payload[10:16])
			}
		}

		// Extract MAC addresses
		var srcMAC, dstMAC string
		if ll := p.LinkLayer(); ll != nil {
			if len(ll.LinkFlow().Src().Raw()) > 0 {
				srcMAC = ll.LinkFlow().Src().String()
			}
			if len(ll.LinkFlow().Dst().Raw()) > 0 {
				dstMAC = ll.LinkFlow().Dst().String()
			}
		}

		return &types.ISIS{
			Timestamp:     p.Metadata().Timestamp.UnixNano(),
			PDUType:       int32(pduType),
			PDUTypeName:   pduTypeName,
			SystemID:      systemID,
			HoldingTime:   holdingTime,
			CircuitType:   circuitType,
			AreaAddresses: areaAddresses,
			SrcMAC:        srcMAC,
			DstMAC:        dstMAC,
			PDULength:     int32(pduLength),
			Version:       int32(version),
		}
	},
	nil,
)

// parseISISTLVs extracts area addresses from IS-IS TLV section
func parseISISTLVs(data []byte, offset, maxLen int) []string {
	var areas []string
	for offset+2 <= len(data) && offset < maxLen {
		tlvType := data[offset]
		tlvLen := int(data[offset+1])
		offset += 2

		if offset+tlvLen > len(data) {
			break
		}

		// TLV type 1 = Area Addresses
		if tlvType == 1 {
			pos := offset
			for pos < offset+tlvLen {
				if pos >= len(data) {
					break
				}
				addrLen := int(data[pos])
				pos++
				if pos+addrLen > offset+tlvLen || pos+addrLen > len(data) {
					break
				}
				areas = append(areas, hex.EncodeToString(data[pos:pos+addrLen]))
				pos += addrLen
			}
		}

		offset += tlvLen
	}
	return areas
}
