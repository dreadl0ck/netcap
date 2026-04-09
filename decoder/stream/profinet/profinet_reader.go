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
	"fmt"
	"sync/atomic"

	"go.uber.org/zap"

	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/core"
	"github.com/dreadl0ck/netcap/types"
)

// PROFINET IO operation types
const (
	OpConnect      = 0 // AR establishment
	OpRelease      = 1 // AR release
	OpRead         = 2 // Read operation
	OpWrite        = 3 // Write operation
	OpControl      = 4 // Control operation
	OpReadImplicit = 5 // Implicit read (for PDEV)
)

// PROFINET service IDs (operation numbers for DCE/RPC)
const (
	ServiceConnect      = 0
	ServiceRelease      = 1
	ServiceRead         = 2
	ServiceWrite        = 3
	ServiceControl      = 4
	ServiceReadImplicit = 5
)

// Alarm types
const (
	AlarmTypeDiagnosis               = 0x0001
	AlarmTypeProcess                 = 0x0002
	AlarmTypePull                    = 0x0003
	AlarmTypePlug                    = 0x0004
	AlarmTypeStatus                  = 0x0005
	AlarmTypeUpdate                  = 0x0006
	AlarmTypeRedundancy              = 0x0007
	AlarmTypeControlledBySupv        = 0x0008
	AlarmTypeReleasedBySupv          = 0x0009
	AlarmTypePlugWrongSubmodule      = 0x000A
	AlarmTypeReturnOfSubmodule       = 0x000B
	AlarmTypeDiagnosisDisappears     = 0x000C
	AlarmTypeMultipleMediaRedundancy = 0x000D
	AlarmTypePortDataChange          = 0x000E
	AlarmTypeSyncDataChange          = 0x000F
	AlarmTypeIsochronousModeProbl    = 0x0010
	AlarmTypeNetworkComponent        = 0x0011
	AlarmTypeTimeDataChange          = 0x0012
	AlarmTypeDynamic                 = 0x0013
	AlarmTypeUploadRetrievalNot      = 0x001E
	AlarmTypePullModule              = 0x001F
)

// Critical operation types (write/control operations that modify device state)
var criticalOperations = map[int]bool{
	OpWrite:   true,
	OpControl: true,
}

type profinetReader struct {
	conversation *core.ConversationInfo
}

// New returns a new PROFINET reader.
func (p *profinetReader) New(conversation *core.ConversationInfo) core.StreamDecoderInterface {
	return &profinetReader{
		conversation: conversation,
	}
}

// Decode parses PROFINET messages from the stream.
func (p *profinetReader) Decode() {
	if Decoder.Writer == nil {
		profinetLog.Error("PROFINET Decoder.Writer is nil")
		return
	}

	var buf bytes.Buffer

	for _, data := range p.conversation.Data {
		buf.Write(data.Raw())
	}

	frameData := buf.Bytes()
	offset := 0

	for offset < len(frameData)-dceRPCHeaderSize {
		// Check for DCE/RPC header
		if !p.isDCERPCHeader(frameData[offset:]) {
			offset++
			continue
		}

		msg, consumed := p.parsePROFINETMessage(frameData[offset:])
		if msg != nil {
			msg.SrcIP = p.conversation.ClientIP
			msg.DstIP = p.conversation.ServerIP
			msg.SrcPort = int32(p.conversation.ClientPort)
			msg.DstPort = int32(p.conversation.ServerPort)

			err := Decoder.Writer.Write(msg)
			if err != nil {
				profinetLog.Error("failed to write PROFINET record", zap.Error(err))
			} else {
				atomic.AddInt64(&Decoder.NumRecordsWritten, 1)
			}
		}

		if consumed > 0 {
			offset += consumed
		} else {
			offset++
		}
	}
}

// isDCERPCHeader checks if the data starts with a valid DCE/RPC header.
func (p *profinetReader) isDCERPCHeader(data []byte) bool {
	if len(data) < dceRPCHeaderSize {
		return false
	}

	// Check version
	version := data[0]
	if version != dceRPCVersion && version != 5 {
		return false
	}

	// Check packet type
	packetType := data[2]
	if !isValidDCERPCPacketType(packetType) {
		return false
	}

	return true
}

// parsePROFINETMessage parses a PROFINET message and returns the record and bytes consumed.
func (p *profinetReader) parsePROFINETMessage(data []byte) (*types.PROFINET, int) {
	if len(data) < dceRPCHeaderSize {
		return nil, 0
	}

	// Parse DCE/RPC header
	version := data[0]
	packetType := data[2]
	packetFlags := data[3]

	// Determine byte order from data representation (byte 4)
	// Bit 4: 0 = big-endian, 1 = little-endian
	littleEndian := (data[4] & 0x10) != 0

	var fragLen uint16
	if littleEndian {
		fragLen = binary.LittleEndian.Uint16(data[8:10])
	} else {
		fragLen = binary.BigEndian.Uint16(data[8:10])
	}

	// Validate fragment length
	totalLen := min(int(fragLen)+dceRPCHeaderSize,
		// Fragment may span multiple TCP segments
		len(data))

	msg := &types.PROFINET{
		Timestamp:     p.conversation.FirstClientPacket.UnixNano(),
		FrameType:     "PNIO-CM",
		FrameTypeName: getDCERPCPacketTypeName(packetType),
		IsRequest:     isRequest(packetType),
	}

	// Set operation type based on DCE/RPC packet type
	msg.OperationType = int32(packetType)
	msg.OperationTypeName = getDCERPCPacketTypeName(packetType)

	// Parse based on packet type
	switch packetType {
	case dceRPCBind, dceRPCAlterContext:
		p.parseBindRequest(msg, data, littleEndian)
	case dceRPCBindACK, dceRPCAlterContextResp:
		p.parseBindResponse(msg, data, littleEndian)
	case dceRPCRequest:
		p.parseRequest(msg, data, littleEndian, version)
	case dceRPCResponse:
		p.parseResponse(msg, data, littleEndian)
	case dceRPCFault:
		msg.IsSecurityRelevant = true
		p.parseFault(msg, data, littleEndian)
	}

	// Include payload if configured
	if decoderconfig.Instance.IncludePayloads && totalLen > dceRPCHeaderSize {
		payloadLen := totalLen - dceRPCHeaderSize
		if payloadLen > 0 && len(data) >= totalLen {
			msg.Payload = make([]byte, payloadLen)
			copy(msg.Payload, data[dceRPCHeaderSize:totalLen])
		}
	}

	// Store sequence info from flags
	if (packetFlags & 0x01) != 0 { // First fragment
		msg.FrameTypeName += " (First)"
	}
	if (packetFlags & 0x02) != 0 { // Last fragment
		msg.FrameTypeName += " (Last)"
	}

	return msg, totalLen
}

// parseBindRequest parses a DCE/RPC Bind or AlterContext request.
func (p *profinetReader) parseBindRequest(msg *types.PROFINET, data []byte, littleEndian bool) {
	if len(data) < dceRPCHeaderSize+16 {
		return
	}

	offset := dceRPCHeaderSize

	// Skip to context list (past max_xmit_frag, max_recv_frag, assoc_group_id)
	// These are 2+2+4 = 8 bytes after header
	if len(data) < offset+8+4 {
		return
	}
	offset += 8

	// Number of context elements
	var numContexts uint8
	if len(data) > offset {
		numContexts = data[offset]
		offset += 4 // Context count (1) + padding (3)
	}

	// Parse first context element to get interface UUID
	if numContexts > 0 && len(data) >= offset+20 {
		// Context ID (2) + num transfer syntaxes (2) = 4 bytes, then Interface UUID (16)
		offset += 4

		// Extract interface UUID
		if len(data) >= offset+16 {
			uuid := data[offset : offset+16]
			msg.VendorID = formatUUID(uuid)

			// Check if it's a known PROFINET interface
			if len(uuid) >= 4 && uuid[0] == 0xde && uuid[1] == 0xa0 {
				serviceNum := uint16(uuid[2])<<8 | uint16(uuid[3])
				msg.ServiceID = int32(serviceNum)
				msg.ServiceName = getServiceNameFromUUID(serviceNum)
			}
		}
	}

	msg.FrameTypeName = "Bind"
	msg.IsSecurityRelevant = true // Session establishment is security-relevant
}

// parseBindResponse parses a DCE/RPC BindACK or AlterContextResp.
func (p *profinetReader) parseBindResponse(msg *types.PROFINET, data []byte, littleEndian bool) {
	if len(data) < dceRPCHeaderSize+8 {
		return
	}

	offset := dceRPCHeaderSize

	// Parse max transmit/receive fragment sizes
	var maxXmit, maxRecv uint16
	if littleEndian {
		maxXmit = binary.LittleEndian.Uint16(data[offset : offset+2])
		maxRecv = binary.LittleEndian.Uint16(data[offset+2 : offset+4])
	} else {
		maxXmit = binary.BigEndian.Uint16(data[offset : offset+2])
		maxRecv = binary.BigEndian.Uint16(data[offset+2 : offset+4])
	}

	msg.BlockLength = int32(maxXmit)
	msg.IODataLength = int32(maxRecv)
	msg.FrameTypeName = "BindACK"
}

// parseRequest parses a DCE/RPC Request containing PROFINET IO data.
func (p *profinetReader) parseRequest(msg *types.PROFINET, data []byte, littleEndian bool, version uint8) {
	if len(data) < dceRPCHeaderSize+8 {
		return
	}

	offset := dceRPCHeaderSize

	// For version 4, parse the object UUID and operation number
	// Object UUID (16 bytes) + Interface UUID (16 bytes) + Activity UUID (16 bytes)
	// + Server boot time (4) + Interface version (4) + Sequence number (4) + Operation number (2)
	// ... this is the connectionless format

	// For connection-oriented (version 5), the format is simpler:
	// alloc_hint (4) + context_id (2) + opnum (2)
	if version == 5 {
		if len(data) < offset+8 {
			return
		}

		var opNum uint16
		if littleEndian {
			opNum = binary.LittleEndian.Uint16(data[offset+6 : offset+8])
		} else {
			opNum = binary.BigEndian.Uint16(data[offset+6 : offset+8])
		}

		msg.ServiceID = int32(opNum)
		msg.ServiceName = getOperationName(int(opNum))
		msg.IsCriticalOperation = criticalOperations[int(opNum)]
		offset += 8
	} else {
		// Connectionless format (version 4) - more complex
		if len(data) < offset+80 {
			return
		}

		// Skip to sequence number and operation number
		// Object UUID (16) + Interface UUID (16) + Activity UUID (16) +
		// Server boot time (4) + Interface version (4) + Sequence number (4) + Operation (2)
		seqNumOffset := offset + 52
		if len(data) >= seqNumOffset+6 {
			var seqNum uint32
			var opNum uint16
			if littleEndian {
				seqNum = binary.LittleEndian.Uint32(data[seqNumOffset : seqNumOffset+4])
				opNum = binary.LittleEndian.Uint16(data[seqNumOffset+4 : seqNumOffset+6])
			} else {
				seqNum = binary.BigEndian.Uint32(data[seqNumOffset : seqNumOffset+4])
				opNum = binary.BigEndian.Uint16(data[seqNumOffset+4 : seqNumOffset+6])
			}

			msg.SequenceNumber = seqNum
			msg.ServiceID = int32(opNum)
			msg.ServiceName = getOperationName(int(opNum))
			msg.IsCriticalOperation = criticalOperations[int(opNum)]
		}
		offset = seqNumOffset + 6
	}

	// Parse PROFINET blocks if present
	p.parseBlocks(msg, data[offset:], littleEndian)
}

// parseResponse parses a DCE/RPC Response containing PROFINET IO data.
func (p *profinetReader) parseResponse(msg *types.PROFINET, data []byte, littleEndian bool) {
	if len(data) < dceRPCHeaderSize+8 {
		return
	}

	offset := dceRPCHeaderSize

	// alloc_hint (4) + context_id (2) + cancel_count (1) + reserved (1)
	offset += 8

	// Parse response blocks
	p.parseBlocks(msg, data[offset:], littleEndian)
}

// parseFault parses a DCE/RPC Fault response.
func (p *profinetReader) parseFault(msg *types.PROFINET, data []byte, littleEndian bool) {
	if len(data) < dceRPCHeaderSize+4 {
		return
	}

	offset := dceRPCHeaderSize

	// Fault status is a 4-byte code
	var faultStatus uint32
	if littleEndian {
		faultStatus = binary.LittleEndian.Uint32(data[offset : offset+4])
	} else {
		faultStatus = binary.BigEndian.Uint32(data[offset : offset+4])
	}

	msg.ErrorType = int32(faultStatus)
	msg.ErrorTypeName = getFaultStatusName(faultStatus)
	msg.IsSecurityRelevant = true
}

// parseBlocks parses PROFINET blocks from the payload.
func (p *profinetReader) parseBlocks(msg *types.PROFINET, data []byte, littleEndian bool) {
	if len(data) < 6 {
		return
	}

	offset := 0

	// Try to parse the first block header
	// Block header: BlockType (2) + BlockLength (2) + BlockVersionHigh (1) + BlockVersionLow (1)
	if len(data) >= offset+6 {
		var blockType, blockLen uint16
		if littleEndian {
			blockType = binary.LittleEndian.Uint16(data[offset : offset+2])
			blockLen = binary.LittleEndian.Uint16(data[offset+2 : offset+4])
		} else {
			blockType = binary.BigEndian.Uint16(data[offset : offset+2])
			blockLen = binary.BigEndian.Uint16(data[offset+2 : offset+4])
		}

		msg.BlockType = int32(blockType)
		msg.BlockTypeName = getBlockTypeName(blockType)
		msg.BlockLength = int32(blockLen)
		msg.BlockVersionHigh = int32(data[offset+4])
		msg.BlockVersionLow = int32(data[offset+5])

		// Check for alarm blocks
		if blockType == BlockTypeAlarmNotificationHigh || blockType == BlockTypeAlarmNotificationLow {
			msg.IsAlarm = true
			p.parseAlarmBlock(msg, data[offset+6:], littleEndian, blockType)
		}

		// Check for diagnosis blocks
		if blockType == BlockTypeDiagnosisData {
			msg.IsDiagnostic = true
		}

		// Parse AR/IO addressing if present
		p.parseARIOAddressing(msg, data[offset+6:], littleEndian)
	}
}

// parseAlarmBlock parses an alarm notification block.
func (p *profinetReader) parseAlarmBlock(msg *types.PROFINET, data []byte, littleEndian bool, blockType uint16) {
	if len(data) < 12 {
		return
	}

	// Alarm header: AlarmType (2) + API (4) + SlotNumber (2) + SubslotNumber (2) + ...
	offset := 0

	var alarmType uint16
	if littleEndian {
		alarmType = binary.LittleEndian.Uint16(data[offset : offset+2])
	} else {
		alarmType = binary.BigEndian.Uint16(data[offset : offset+2])
	}

	msg.AlarmType = int32(alarmType)
	msg.AlarmTypeName = getAlarmTypeName(alarmType)
	msg.AlarmPriority = 1 // Low priority
	if blockType == BlockTypeAlarmNotificationHigh {
		msg.AlarmPriority = 2 // High priority
	}

	offset += 2

	// API
	if len(data) >= offset+4 {
		if littleEndian {
			msg.API = binary.LittleEndian.Uint32(data[offset : offset+4])
		} else {
			msg.API = binary.BigEndian.Uint32(data[offset : offset+4])
		}
		offset += 4
	}

	// Slot and Subslot
	if len(data) >= offset+4 {
		if littleEndian {
			msg.SlotNumber = int32(binary.LittleEndian.Uint16(data[offset : offset+2]))
			msg.SubslotNumber = int32(binary.LittleEndian.Uint16(data[offset+2 : offset+4]))
		} else {
			msg.SlotNumber = int32(binary.BigEndian.Uint16(data[offset : offset+2]))
			msg.SubslotNumber = int32(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		}
	}
}

// parseARIOAddressing parses Application Relationship and IO addressing.
func (p *profinetReader) parseARIOAddressing(msg *types.PROFINET, data []byte, littleEndian bool) {
	if len(data) < 8 {
		return
	}

	// Look for AR UUID and API/Slot/Subslot info in the block data
	// This is present in IOD blocks (Read/Write)
	offset := 0

	// Check if we have API + Slot + Subslot pattern (4+2+2 = 8 bytes)
	if len(data) >= offset+8 {
		var api uint32
		var slot, subslot uint16

		if littleEndian {
			api = binary.LittleEndian.Uint32(data[offset : offset+4])
			slot = binary.LittleEndian.Uint16(data[offset+4 : offset+6])
			subslot = binary.LittleEndian.Uint16(data[offset+6 : offset+8])
		} else {
			api = binary.BigEndian.Uint32(data[offset : offset+4])
			slot = binary.BigEndian.Uint16(data[offset+4 : offset+6])
			subslot = binary.BigEndian.Uint16(data[offset+6 : offset+8])
		}

		// Only set if they look valid (API is usually 0 for standard PROFINET)
		if api <= 0xFFFFFF && slot <= 0x7FFF && subslot <= 0x7FFF {
			msg.API = api
			msg.SlotNumber = int32(slot)
			msg.SubslotNumber = int32(subslot)
		}
	}
}

// isRequest returns true if the packet type represents a request.
func isRequest(packetType uint8) bool {
	switch packetType {
	case dceRPCRequest, dceRPCBind, dceRPCAlterContext, dceRPCPing, dceRPCAuth3:
		return true
	}
	return false
}

// getOperationName returns the human-readable name for a PROFINET operation.
func getOperationName(op int) string {
	switch op {
	case OpConnect:
		return "Connect"
	case OpRelease:
		return "Release"
	case OpRead:
		return "Read"
	case OpWrite:
		return "Write"
	case OpControl:
		return "Control"
	case OpReadImplicit:
		return "ReadImplicit"
	default:
		return "Unknown"
	}
}

// getAlarmTypeName returns the human-readable name for an alarm type.
func getAlarmTypeName(t uint16) string {
	switch t {
	case AlarmTypeDiagnosis:
		return "Diagnosis"
	case AlarmTypeProcess:
		return "Process"
	case AlarmTypePull:
		return "Pull"
	case AlarmTypePlug:
		return "Plug"
	case AlarmTypeStatus:
		return "Status"
	case AlarmTypeUpdate:
		return "Update"
	case AlarmTypeRedundancy:
		return "Redundancy"
	case AlarmTypeControlledBySupv:
		return "ControlledBySupervisor"
	case AlarmTypeReleasedBySupv:
		return "ReleasedBySupervisor"
	case AlarmTypePlugWrongSubmodule:
		return "PlugWrongSubmodule"
	case AlarmTypeReturnOfSubmodule:
		return "ReturnOfSubmodule"
	case AlarmTypeDiagnosisDisappears:
		return "DiagnosisDisappears"
	case AlarmTypeMultipleMediaRedundancy:
		return "MultipleMediaRedundancy"
	case AlarmTypePortDataChange:
		return "PortDataChange"
	case AlarmTypeSyncDataChange:
		return "SyncDataChange"
	case AlarmTypeIsochronousModeProbl:
		return "IsochronousModeProblem"
	case AlarmTypeNetworkComponent:
		return "NetworkComponent"
	case AlarmTypeTimeDataChange:
		return "TimeDataChange"
	case AlarmTypeDynamic:
		return "Dynamic"
	case AlarmTypeUploadRetrievalNot:
		return "UploadRetrievalNotification"
	case AlarmTypePullModule:
		return "PullModule"
	default:
		if t >= 0x0020 && t <= 0x007F {
			return "ManufacturerSpecific"
		}
		if t >= 0x0100 && t <= 0x7FFF {
			return "Reserved"
		}
		return "Unknown"
	}
}

// getFaultStatusName returns the human-readable name for a DCE/RPC fault status.
func getFaultStatusName(status uint32) string {
	switch status {
	case 0x00000000:
		return "Success"
	case 0x1C000001:
		return "NCA_S_FAULT_OTHER"
	case 0x1C000002:
		return "NCA_S_FAULT_ACCESS_DENIED"
	case 0x1C000003:
		return "NCA_S_FAULT_NDR"
	case 0x1C000008:
		return "NCA_S_FAULT_CANT_PERFORM"
	case 0x1C00000D:
		return "NCA_S_FAULT_OBJECT_NOT_FOUND"
	case 0x1C010002:
		return "NCA_S_OP_RNG_ERROR"
	case 0x1C010003:
		return "NCA_S_UNK_IF"
	case 0x1C010006:
		return "NCA_S_WRONG_BOOT_TIME"
	case 0x1C010009:
		return "NCA_S_YOU_CRASHED"
	case 0x1C01000B:
		return "NCA_S_PROTO_ERROR"
	case 0x1C010014:
		return "NCA_S_COMM_FAILURE"
	default:
		return "Unknown"
	}
}

// getServiceNameFromUUID returns the service name based on the PROFINET interface UUID.
func getServiceNameFromUUID(serviceNum uint16) string {
	switch serviceNum {
	case 0x0000:
		return "EndpointMapper"
	case 0x0001:
		return "PNIO"
	case 0x0002:
		return "PNIO-CM"
	case 0x0003:
		return "PNIO-RT"
	case 0x0004:
		return "PNIO-MRP"
	case 0x0005:
		return "PNIO-PTCP"
	default:
		return "Unknown"
	}
}

// formatUUID formats a 16-byte UUID as a string.
func formatUUID(uuid []byte) string {
	if len(uuid) < 16 {
		return ""
	}

	return fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		binary.LittleEndian.Uint32(uuid[0:4]),
		binary.LittleEndian.Uint16(uuid[4:6]),
		binary.LittleEndian.Uint16(uuid[6:8]),
		uuid[8], uuid[9],
		uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15])
}
