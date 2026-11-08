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

package profinet

import (
	"bytes"
	"encoding/binary"

	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/internal/decoder"
	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	logging "github.com/dreadl0ck/netcap/internal/logger"
	"github.com/dreadl0ck/netcap/types"
)

var profinetLog = zap.NewNop()

const servicePROFINET = "PROFINET"

// PROFINET uses DCE/RPC for Context Manager (CM) communication.
// The DCE/RPC header format for connection-oriented RPC:
// - Version: 1 byte (should be 5 for RPC version 5.x)
// - Minor Version: 1 byte
// - Packet Type: 1 byte
// - Packet Flags: 1 byte
// - Data Representation: 4 bytes
// - Fragment Length: 2 bytes
// - Auth Length: 2 bytes
// - Call ID: 4 bytes
const (
	// DCE/RPC header size (connection-oriented)
	dceRPCHeaderSize = 24

	// DCE/RPC version for PROFINET
	dceRPCVersion = 4

	// DCE/RPC packet types
	dceRPCRequest          = 0x00
	dceRPCPing             = 0x01
	dceRPCResponse         = 0x02
	dceRPCFault            = 0x03
	dceRPCWorking          = 0x04
	dceRPCNoCall           = 0x05
	dceRPCReject           = 0x06
	dceRPCACK              = 0x07
	dceRPCCL_Cancel        = 0x08
	dceRPCFACK             = 0x09
	dceRPCCancelACK        = 0x0A
	dceRPCBind             = 0x0B
	dceRPCBindACK          = 0x0C
	dceRPCBindNAK          = 0x0D
	dceRPCAlterContext     = 0x0E
	dceRPCAlterContextResp = 0x0F
	dceRPCShutdown         = 0x11
	dceRPCAuth3            = 0x10
)

// PROFINET block types
const (
	BlockTypeAlarmNotificationHigh     = 0x0001
	BlockTypeAlarmNotificationLow      = 0x0002
	BlockTypeIODWriteReqHeader         = 0x0008
	BlockTypeIODReadReqHeader          = 0x0009
	BlockTypeIODWriteResHeader         = 0x8008
	BlockTypeIODReadResHeader          = 0x8009
	BlockTypeARBlockReq                = 0x0101
	BlockTypeIOCRBlockReq              = 0x0102
	BlockTypeAlarmCRBlockReq           = 0x0103
	BlockTypeExpectedSubmoduleBlockReq = 0x0104
	BlockTypeARBlockRes                = 0x8101
	BlockTypeIOCRBlockRes              = 0x8102
	BlockTypeAlarmCRBlockRes           = 0x8103
	BlockTypeModuleDiffBlock           = 0x8104
	BlockTypeARRPCBlockReq             = 0x0105
	BlockTypeARRPCBlockRes             = 0x8105
	BlockTypeIODControlReq             = 0x0110
	BlockTypeIODControlRes             = 0x8110
	BlockTypeReleaseBlock              = 0x0114
	BlockTypeIOXBlockReq               = 0x0116
	BlockTypeIOXBlockRes               = 0x8116
	BlockTypeReadRecordInputReq        = 0x8028
	BlockTypeReadRecordOutputReq       = 0x8029
	BlockTypeI_M0                      = 0x0020
	BlockTypeI_M1                      = 0x0021
	BlockTypeI_M2                      = 0x0022
	BlockTypeI_M3                      = 0x0023
	BlockTypeI_M4                      = 0x0024
	BlockTypeDiagnosisData             = 0x0010
)

// Decoder for protocol analysis and writing audit records to disk.
var Decoder = &decoder.StreamDecoder{
	Type:        types.Type_NC_PROFINET,
	Name:        servicePROFINET,
	Description: "PROFINET is an industrial Ethernet standard for automation and real-time process control",
	PostInit: func(d *decoder.StreamDecoder) error {
		var err error
		profinetLog, _, err = logging.InitZapLogger(
			decoderconfig.Instance.Out,
			"profinet",
			decoderconfig.Instance.Debug,
		)
		return err
	},
	Specificity: core.SpecificityMagic,

	CanDecode: func(client, server []byte) bool {
		// Check both directions for PROFINET traffic over DCE/RPC
		return canDecodePROFINET(client) || canDecodePROFINET(server)
	},
	DeInit: func(sd *decoder.StreamDecoder) error {
		return profinetLog.Sync()
	},
	Factory: &profinetReader{},
	Typ:     core.TCP, // PROFINET CM uses TCP port 34964
}

// RPC version/packet type alone cannot identify PNIO. Match its full interface
// UUID at a defined header/context offset, respecting the wire byte order.
func canDecodePROFINET(data []byte) bool {
	if len(data) < 16 || (data[4] != 0 && data[4] != 0x10) || data[5] != 0 || data[6] != 0 {
		return false
	}
	var order binary.ByteOrder = binary.BigEndian
	if data[4] == 0x10 {
		order = binary.LittleEndian
	}
	if data[0] == 4 {
		// Connectionless RPC has an 80-byte header and packet type at byte 1.
		return len(data) >= 80 && data[1] <= dceRPCCancelACK &&
			profinetUUID(data[24:40], order) && order.Uint32(data[60:64]) == 1 &&
			order.Uint16(data[68:70]) <= 5
	}
	if data[0] != 5 || data[1] != 0 || data[7] != 0 || (data[2] != dceRPCBind && data[2] != dceRPCAlterContext) {
		return false
	}
	n, auth := int(order.Uint16(data[8:10])), int(order.Uint16(data[10:12]))
	if n < 72 || auth > n-24 || len(data) < 28 {
		return false
	}
	end := n
	if auth != 0 {
		end -= auth + 8
	}
	data = data[:min(end, len(data))]
	if len(data) < 28 || data[24] == 0 || data[25] != 0 || data[26] != 0 || data[27] != 0 {
		return false
	}
	matched := false
	for count, offset := int(data[24]), 28; count > 0; count-- {
		if offset+24 > len(data) || data[offset+2] == 0 || data[offset+3] != 0 {
			return false
		}
		next := offset + 24 + 20*int(data[offset+2])
		if next > end || next > len(data) {
			return false
		}
		matched = matched || profinetUUID(data[offset+4:offset+20], order)
		offset = next
	}
	return matched
}

func profinetUUID(uuid []byte, order binary.ByteOrder) bool {
	id := order.Uint32(uuid[:4])
	return id >= 0xdea00000 && id <= 0xdea00005 && order.Uint16(uuid[4:6]) == 0x6c97 &&
		order.Uint16(uuid[6:8]) == 0x11d1 && bytes.Equal(uuid[8:], []byte{0x82, 0x71, 0, 0xa0, 0x24, 0x42, 0xdf, 0x7d})
}

// isValidDCERPCPacketType checks if the packet type is a valid DCE/RPC type.
func isValidDCERPCPacketType(t uint8) bool {
	switch t {
	case dceRPCRequest, dceRPCPing, dceRPCResponse, dceRPCFault,
		dceRPCWorking, dceRPCNoCall, dceRPCReject, dceRPCACK,
		dceRPCCL_Cancel, dceRPCFACK, dceRPCCancelACK, dceRPCBind,
		dceRPCBindACK, dceRPCBindNAK, dceRPCAlterContext,
		dceRPCAlterContextResp, dceRPCShutdown, dceRPCAuth3:
		return true
	}
	return false
}

// getDCERPCPacketTypeName returns the human-readable name for a DCE/RPC packet type.
func getDCERPCPacketTypeName(t uint8) string {
	switch t {
	case dceRPCRequest:
		return "Request"
	case dceRPCPing:
		return "Ping"
	case dceRPCResponse:
		return "Response"
	case dceRPCFault:
		return "Fault"
	case dceRPCWorking:
		return "Working"
	case dceRPCNoCall:
		return "NoCall"
	case dceRPCReject:
		return "Reject"
	case dceRPCACK:
		return "ACK"
	case dceRPCCL_Cancel:
		return "CL_Cancel"
	case dceRPCFACK:
		return "FACK"
	case dceRPCCancelACK:
		return "CancelACK"
	case dceRPCBind:
		return "Bind"
	case dceRPCBindACK:
		return "BindACK"
	case dceRPCBindNAK:
		return "BindNAK"
	case dceRPCAlterContext:
		return "AlterContext"
	case dceRPCAlterContextResp:
		return "AlterContextResp"
	case dceRPCShutdown:
		return "Shutdown"
	case dceRPCAuth3:
		return "Auth3"
	default:
		return "Unknown"
	}
}

// getBlockTypeName returns the human-readable name for a PROFINET block type.
func getBlockTypeName(t uint16) string {
	switch t {
	case BlockTypeAlarmNotificationHigh:
		return "AlarmNotificationHigh"
	case BlockTypeAlarmNotificationLow:
		return "AlarmNotificationLow"
	case BlockTypeIODWriteReqHeader:
		return "IODWriteReqHeader"
	case BlockTypeIODReadReqHeader:
		return "IODReadReqHeader"
	case BlockTypeIODWriteResHeader:
		return "IODWriteResHeader"
	case BlockTypeIODReadResHeader:
		return "IODReadResHeader"
	case BlockTypeARBlockReq:
		return "ARBlockReq"
	case BlockTypeIOCRBlockReq:
		return "IOCRBlockReq"
	case BlockTypeAlarmCRBlockReq:
		return "AlarmCRBlockReq"
	case BlockTypeExpectedSubmoduleBlockReq:
		return "ExpectedSubmoduleBlockReq"
	case BlockTypeARBlockRes:
		return "ARBlockRes"
	case BlockTypeIOCRBlockRes:
		return "IOCRBlockRes"
	case BlockTypeAlarmCRBlockRes:
		return "AlarmCRBlockRes"
	case BlockTypeModuleDiffBlock:
		return "ModuleDiffBlock"
	case BlockTypeARRPCBlockReq:
		return "ARRPCBlockReq"
	case BlockTypeARRPCBlockRes:
		return "ARRPCBlockRes"
	case BlockTypeIODControlReq:
		return "IODControlReq"
	case BlockTypeIODControlRes:
		return "IODControlRes"
	case BlockTypeReleaseBlock:
		return "ReleaseBlock"
	case BlockTypeIOXBlockReq:
		return "IOXBlockReq"
	case BlockTypeIOXBlockRes:
		return "IOXBlockRes"
	case BlockTypeI_M0:
		return "I&M0"
	case BlockTypeI_M1:
		return "I&M1"
	case BlockTypeI_M2:
		return "I&M2"
	case BlockTypeI_M3:
		return "I&M3"
	case BlockTypeI_M4:
		return "I&M4"
	case BlockTypeDiagnosisData:
		return "DiagnosisData"
	default:
		if t&0x8000 != 0 {
			return "ResponseBlock"
		}
		return "Unknown"
	}
}
