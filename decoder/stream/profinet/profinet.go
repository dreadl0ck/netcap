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
	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/decoder"
	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/core"
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
	dceRPCRequest      = 0x00
	dceRPCPing         = 0x01
	dceRPCResponse     = 0x02
	dceRPCFault        = 0x03
	dceRPCWorking      = 0x04
	dceRPCNoCall       = 0x05
	dceRPCReject       = 0x06
	dceRPCACK          = 0x07
	dceRPCCL_Cancel    = 0x08
	dceRPCFACK         = 0x09
	dceRPCCancelACK    = 0x0A
	dceRPCBind         = 0x0B
	dceRPCBindACK      = 0x0C
	dceRPCBindNAK      = 0x0D
	dceRPCAlterContext = 0x0E
	dceRPCAlterContextResp = 0x0F
	dceRPCShutdown     = 0x11
	dceRPCAuth3        = 0x10
)

// PROFINET IO interface UUID prefix (first 4 bytes for quick matching)
// Full UUID: dea00001-6c97-11d1-8271-00a02442df7d
var profinetIOUUID = []byte{0xde, 0xa0, 0x00, 0x01}

// PROFINET block types
const (
	BlockTypeAlarmNotificationHigh      = 0x0001
	BlockTypeAlarmNotificationLow       = 0x0002
	BlockTypeIODWriteReqHeader          = 0x0008
	BlockTypeIODReadReqHeader           = 0x0009
	BlockTypeIODWriteResHeader          = 0x8008
	BlockTypeIODReadResHeader           = 0x8009
	BlockTypeARBlockReq                 = 0x0101
	BlockTypeIOCRBlockReq               = 0x0102
	BlockTypeAlarmCRBlockReq            = 0x0103
	BlockTypeExpectedSubmoduleBlockReq  = 0x0104
	BlockTypeARBlockRes                 = 0x8101
	BlockTypeIOCRBlockRes               = 0x8102
	BlockTypeAlarmCRBlockRes            = 0x8103
	BlockTypeModuleDiffBlock            = 0x8104
	BlockTypeARRPCBlockReq              = 0x0105
	BlockTypeARRPCBlockRes              = 0x8105
	BlockTypeIODControlReq              = 0x0110
	BlockTypeIODControlRes              = 0x8110
	BlockTypeReleaseBlock               = 0x0114
	BlockTypeIOXBlockReq                = 0x0116
	BlockTypeIOXBlockRes                = 0x8116
	BlockTypeReadRecordInputReq         = 0x8028
	BlockTypeReadRecordOutputReq        = 0x8029
	BlockTypeI_M0                       = 0x0020
	BlockTypeI_M1                       = 0x0021
	BlockTypeI_M2                       = 0x0022
	BlockTypeI_M3                       = 0x0023
	BlockTypeI_M4                       = 0x0024
	BlockTypeDiagnosisData              = 0x0010
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

// canDecodePROFINET checks if the data looks like a PROFINET message.
// PROFINET uses DCE/RPC as transport, so we look for DCE/RPC headers
// with PROFINET-specific interface UUIDs.
func canDecodePROFINET(data []byte) bool {
	if len(data) < dceRPCHeaderSize {
		return false
	}

	// Check DCE/RPC version (byte 0 should be 4 for PROFINET)
	// PROFINET uses a special version of DCE/RPC
	version := data[0]
	if version != dceRPCVersion && version != 5 {
		return false
	}

	// Check packet type (byte 2) is valid
	packetType := data[2]
	if !isValidDCERPCPacketType(packetType) {
		return false
	}

	// For Bind and Request packets, check if the interface UUID matches PROFINET
	// The interface UUID starts at offset 24 in Bind packets
	if packetType == dceRPCBind || packetType == dceRPCAlterContext {
		if len(data) < dceRPCHeaderSize+16 {
			return false
		}
		// Check for PROFINET IO UUID prefix at expected offset
		// After the 24-byte DCE/RPC header, there's context negotiation
		// which includes the interface UUID
		return containsPROFINETUUID(data[dceRPCHeaderSize:])
	}

	// For other packet types, be more permissive as they may be part of
	// an established PROFINET session
	// Check fragment length sanity
	fragLen := uint16(data[8]) | uint16(data[9])<<8
	if fragLen < 4 || fragLen > 65535 {
		// May be big-endian
		fragLen = uint16(data[9]) | uint16(data[8])<<8
		if fragLen < 4 || fragLen > 65535 {
			return false
		}
	}

	return true
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

// containsPROFINETUUID checks if the data contains the PROFINET IO UUID.
func containsPROFINETUUID(data []byte) bool {
	if len(data) < 4 {
		return false
	}

	// Search for PROFINET UUID prefix in the first 64 bytes
	limit := 64
	if len(data) < limit {
		limit = len(data)
	}

	for i := 0; i <= limit-4; i++ {
		if data[i] == profinetIOUUID[0] &&
			data[i+1] == profinetIOUUID[1] &&
			data[i+2] == profinetIOUUID[2] &&
			data[i+3] == profinetIOUUID[3] {
			return true
		}
	}

	// Also check for variant UUIDs used in PROFINET
	// DEA00000-6C97-11D1-8271-00A02442DF7D (Endpoint Mapper)
	// DEA00001-6C97-11D1-8271-00A02442DF7D (PNIO)
	// DEA00002-6C97-11D1-8271-00A02442DF7D (PNIO-CM)
	for i := 0; i <= limit-4; i++ {
		if data[i] == 0xde && data[i+1] == 0xa0 &&
			data[i+2] == 0x00 && data[i+3] <= 0x05 {
			return true
		}
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

