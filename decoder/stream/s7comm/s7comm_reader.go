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

package s7comm

import (
	"bytes"
	"encoding/binary"
	"sync/atomic"

	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/decoder/core"
	"github.com/dreadl0ck/netcap/types"
)

type s7commReader struct {
	conversation *core.ConversationInfo
}

// New returns a new S7comm reader.
func (s *s7commReader) New(conversation *core.ConversationInfo) core.StreamDecoderInterface {
	return &s7commReader{
		conversation: conversation,
	}
}

// Decode parses S7comm messages from the stream.
func (s *s7commReader) Decode() {
	if Decoder.Writer == nil {
		s7commLog.Error("S7Comm Decoder.Writer is nil")
		return
	}

	var buf bytes.Buffer

	for _, data := range s.conversation.Data {
		buf.Write(data.Raw())
	}

	frameData := buf.Bytes()
	offset := 0

	for offset < len(frameData)-minTPKTSize {
		// Check for TPKT header
		if !s.isTPKTHeader(frameData[offset:]) {
			offset++
			continue
		}

		msg, consumed := s.parseTPKTMessage(frameData[offset:])
		if msg != nil {
			msg.SrcIP = s.conversation.ClientIP
			msg.DstIP = s.conversation.ServerIP
			msg.SrcPort = int32(s.conversation.ClientPort)
			msg.DstPort = int32(s.conversation.ServerPort)

			err := Decoder.Writer.Write(msg)
			if err != nil {
				s7commLog.Error("failed to write S7Comm record", zap.Error(err))
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

// isTPKTHeader checks if the data starts with a valid TPKT header.
func (s *s7commReader) isTPKTHeader(data []byte) bool {
	if len(data) < minTPKTSize {
		return false
	}

	// TPKT version must be 3
	if data[0] != tpktVersion {
		return false
	}

	// Reserved byte should be 0
	if data[1] != 0x00 {
		return false
	}

	// Get TPKT length (big-endian)
	tpktLength := int(data[2])<<8 | int(data[3])
	if tpktLength < minTPKTSize {
		return false
	}

	return true
}

// parseTPKTMessage parses a TPKT/COTP/S7comm message and returns the parsed record and bytes consumed.
func (s *s7commReader) parseTPKTMessage(data []byte) (*types.S7Comm, int) {
	if len(data) < minTPKTSize {
		return nil, 0
	}

	// Parse TPKT header
	tpktVersion := int32(data[0])
	tpktLength := int(data[2])<<8 | int(data[3])

	// Validate we have enough data
	if len(data) < tpktLength {
		return nil, 0
	}

	msg := &types.S7Comm{
		Timestamp:   s.conversation.FirstClientPacket.UnixNano(),
		TPKTVersion: tpktVersion,
		TPKTLength:  int32(tpktLength),
	}

	// Parse COTP header
	cotpOffset := minTPKTSize
	if cotpOffset >= len(data) {
		return msg, tpktLength
	}

	cotpLength := int(data[cotpOffset])
	if cotpOffset+cotpLength+1 > len(data) {
		return msg, tpktLength
	}

	msg.COTPLength = int32(cotpLength)

	// Parse COTP PDU type
	if cotpOffset+1 < len(data) {
		pduType := int(data[cotpOffset+1])
		msg.COTPPDUType = int32(pduType)
		msg.COTPPDUTypeName = getCOTPPDUTypeName(pduType)

		// Parse based on PDU type
		pduTypeClass := pduType & 0xF0
		switch pduTypeClass {
		case COTPTypeCR, COTPTypeCC:
			// Connection Request / Connection Confirm
			s.parseCOTPConnection(msg, data[cotpOffset:], cotpLength)
		case COTPTypeDT:
			// Data Transfer - parse S7comm payload
			s.parseCOTPData(msg, data[cotpOffset:], cotpLength)
		case COTPTypeDR, COTPTypeDC:
			// Disconnect Request / Disconnect Confirm
			if cotpLength >= 6 && cotpOffset+6 <= len(data) {
				msg.COTPDestRef = int32(binary.BigEndian.Uint16(data[cotpOffset+2 : cotpOffset+4]))
				msg.COTPSrcRef = int32(binary.BigEndian.Uint16(data[cotpOffset+4 : cotpOffset+6]))
			}
		}
	}

	return msg, tpktLength
}

// parseCOTPConnection parses a COTP Connection Request/Confirm message.
func (s *s7commReader) parseCOTPConnection(msg *types.S7Comm, data []byte, cotpLength int) {
	if len(data) < 7 {
		return
	}

	// CR/CC format:
	// Byte 0: Length indicator
	// Byte 1: PDU type (CR=0x0E, CC=0x0D)
	// Bytes 2-3: Destination reference
	// Bytes 4-5: Source reference
	// Byte 6: Class + Options

	msg.COTPDestRef = int32(binary.BigEndian.Uint16(data[2:4]))
	msg.COTPSrcRef = int32(binary.BigEndian.Uint16(data[4:6]))

	if len(data) > 6 {
		msg.COTPClass = int32(data[6] >> 4)
	}
}

// parseCOTPData parses a COTP Data Transfer message and its S7comm payload.
func (s *s7commReader) parseCOTPData(msg *types.S7Comm, data []byte, cotpLength int) {
	if len(data) < 3 {
		return
	}

	// DT format:
	// Byte 0: Length indicator (usually 2)
	// Byte 1: PDU type (0x0F for DT, lower nibble = sequence)
	// Byte 2: TPDU number and EOT flag (bit 7 = last data unit)

	if cotpLength >= 2 && len(data) > 2 {
		tpduNumber := data[2] & 0x7F
		lastDataUnit := (data[2] & 0x80) != 0
		msg.COTPTPDUNumber = int32(tpduNumber)
		msg.COTPLastDataUnit = lastDataUnit
	}

	// Parse S7comm payload
	s7commOffset := 1 + cotpLength
	if s7commOffset >= len(data) {
		return
	}

	s.parseS7Comm(msg, data[s7commOffset:])
}

// parseS7Comm parses the S7comm protocol header and payload.
func (s *s7commReader) parseS7Comm(msg *types.S7Comm, data []byte) {
	if len(data) < 10 {
		return
	}

	// S7comm header format:
	// Byte 0: Protocol ID (0x32 for classic, 0x72 for S7Comm Plus)
	// Byte 1: Message type
	// Bytes 2-3: Reserved (always 0x0000)
	// Bytes 4-5: PDU reference
	// Bytes 6-7: Parameter length
	// Bytes 8-9: Data length
	// (For Ack-Data: Bytes 10-11: Error class/code)

	protocolId := int(data[0])

	// Handle S7Comm Plus (TIA Portal / S7-1200/1500)
	if protocolId == s7commPlusProtocolID {
		s.parseS7CommPlus(msg, data)
		return
	}

	// Classic S7Comm
	if protocolId != s7commProtocolID {
		return
	}

	msg.ProtocolId = int32(protocolId)
	msg.MessageType = int32(data[1])
	msg.MessageTypeName = getMessageTypeName(int(data[1]))
	msg.Reserved = int32(binary.BigEndian.Uint16(data[2:4]))
	msg.PDUReference = int32(binary.BigEndian.Uint16(data[4:6]))
	msg.ParameterLength = int32(binary.BigEndian.Uint16(data[6:8]))
	msg.DataLength = int32(binary.BigEndian.Uint16(data[8:10]))

	paramOffset := 10

	// For Ack-Data messages, there's an error class/code after the base header
	if msg.MessageType == S7CommMsgTypeAckData {
		if len(data) >= 12 {
			msg.ErrorClass = int32(data[10])
			msg.ErrorCode = int32(data[11])
			msg.ErrorName = getErrorName(int(data[10]), int(data[11]))
			paramOffset = 12
		}
	}

	// Parse parameter section
	if msg.ParameterLength > 0 && paramOffset < len(data) {
		endOffset := min(paramOffset+int(msg.ParameterLength), len(data))
		s.parseS7Parameters(msg, data[paramOffset:endOffset])
	}

	// Parse data section
	dataOffset := paramOffset + int(msg.ParameterLength)
	if msg.DataLength > 0 && dataOffset < len(data) {
		endOffset := min(dataOffset+int(msg.DataLength), len(data))
		s.parseS7Data(msg, data[dataOffset:endOffset])
	}
}

// parseS7CommPlus parses the cleartext framing of S7Comm Plus (TIA Portal)
// messages used by S7-1200/1500 PLCs. The S7CommPlus header itself is in the
// clear (protocol id, version, data length, opcode) even though the request/
// response body is protected by session-keyed integrity material. We therefore
// extract what is observable and explicitly flag the payload as obscured so an
// analyst can see the visibility gap (CISA AA26-231A named limitation): the
// connection is proven, but the function code often cannot be determined.
//
// S7CommPlus header layout (classic framing):
//
//	Byte 0:    Protocol ID (0x72)
//	Byte 1:    Protocol version (0x01, 0x02, 0x03)
//	Bytes 2-3: Data length (big-endian)
//	Byte 4:    Opcode (0x31 Request, 0x32 Response, 0x33 Notification)
//	Bytes 5-6: Reserved / function (version dependent)
//	Byte 7:    Function / sequence (version dependent)
func (s *s7commReader) parseS7CommPlus(msg *types.S7Comm, data []byte) {
	if len(data) < 2 {
		return
	}

	msg.ProtocolId = int32(data[0])
	msg.MessageTypeName = "S7Comm Plus"

	// Newer TIA Portal features are always security-relevant, and the payload
	// is integrity-obscured so we cannot determine the function code.
	msg.IsSecurityRelevant = true
	msg.PayloadObscured = true

	// Protocol version byte.
	msg.MessageType = int32(data[1])

	// Data length (bytes 2-3), when present.
	if len(data) >= 4 {
		msg.DataLength = int32(binary.BigEndian.Uint16(data[2:4]))
	}

	// Opcode (byte 4) identifies request/response/notification. This is in the
	// clear and lets us distinguish direction and message class even though the
	// body is protected.
	if len(data) >= 5 {
		opcode := int32(data[4])
		msg.S7PlusOpcode = opcode
		msg.S7PlusOpcodeName = getS7PlusOpcodeName(int(data[4]))
	}

	// Function/data field (version dependent, byte 6 or 7). Best-effort only.
	if len(data) >= 7 {
		msg.S7PlusFunction = int32(data[6])
	}

	s7commLog.Debug("S7Comm Plus message detected",
		zap.Int("length", len(data)),
		zap.Int32("opcode", msg.S7PlusOpcode),
		zap.String("opcodeName", msg.S7PlusOpcodeName),
	)
}

// getS7PlusOpcodeName returns the human-readable name for an S7CommPlus opcode.
func getS7PlusOpcodeName(opcode int) string {
	switch opcode {
	case s7PlusOpcodeRequest:
		return "Request"
	case s7PlusOpcodeResponse:
		return "Response"
	case s7PlusOpcodeNotification:
		return "Notification"
	default:
		return "Unknown"
	}
}

// parseS7Parameters parses the S7comm parameter section.
func (s *s7commReader) parseS7Parameters(msg *types.S7Comm, data []byte) {
	if len(data) < 1 {
		return
	}

	functionCode := int(data[0])
	msg.FunctionCode = int32(functionCode)
	msg.FunctionName = getFunctionName(functionCode)

	// Determine if this is a critical operation
	switch functionCode {
	case S7FuncWriteVar, S7FuncPLCStop, S7FuncDownloadBlock, S7FuncPIService:
		msg.IsCriticalOperation = true
	case S7FuncSetupCommunication:
		msg.IsSecurityRelevant = true
	}

	switch functionCode {
	case S7FuncSetupCommunication:
		s.parseSetupCommunication(msg, data)
	case S7FuncReadVar:
		s.parseReadWriteVar(msg, data)
	case S7FuncWriteVar:
		msg.IsCriticalOperation = true
		s.parseReadWriteVar(msg, data)
	case S7FuncRequestDownload, S7FuncDownloadBlock, S7FuncDownloadEnded:
		msg.IsCriticalOperation = true
		s.parseDownloadUpload(msg, data)
	case S7FuncStartUpload, S7FuncUpload, S7FuncEndUpload:
		s.parseDownloadUpload(msg, data)
	case S7FuncPIService:
		msg.IsCriticalOperation = true
		s.parsePIService(msg, data)
	case S7FuncPLCStop:
		msg.IsCriticalOperation = true
	}

	// Check for UserData messages
	if msg.MessageType == S7CommMsgTypeUserData && len(data) >= 4 {
		s.parseUserData(msg, data)
	}
}

// parseSetupCommunication parses Setup Communication parameters.
func (s *s7commReader) parseSetupCommunication(msg *types.S7Comm, data []byte) {
	// Setup Communication format (request):
	// Byte 0: Function code (0xF0)
	// Byte 1: Reserved
	// Bytes 2-3: Max AmQ Calling (jobs client->PLC)
	// Bytes 4-5: Max AmQ Called (jobs PLC->client)
	// Bytes 6-7: PDU Size

	if len(data) >= 8 {
		msg.MaxAmqCalling = int32(binary.BigEndian.Uint16(data[2:4]))
		msg.MaxAmqCalled = int32(binary.BigEndian.Uint16(data[4:6]))
		msg.PDUSize = int32(binary.BigEndian.Uint16(data[6:8]))
		msg.IsSecurityRelevant = true
	}
}

// parseReadWriteVar parses Read/Write Variable parameters.
func (s *s7commReader) parseReadWriteVar(msg *types.S7Comm, data []byte) {
	// Read/Write Var format (request):
	// Byte 0: Function code (0x04 or 0x05)
	// Byte 1: Item count
	// Following: Item specifications (12 bytes each for S7-Any)

	if len(data) < 2 {
		return
	}

	itemCount := int(data[1])
	msg.ItemCount = int32(itemCount)

	// Parse items
	offset := 2
	items := make([]*types.S7CommItem, 0, itemCount)

	for i := 0; i < itemCount && offset < len(data); i++ {
		item, consumed := s.parseS7AnyItem(data[offset:])
		if item != nil {
			items = append(items, item)
		}
		if consumed > 0 {
			offset += consumed
		} else {
			break
		}
	}

	msg.Items = items
}

// parseS7AnyItem parses an S7-Any addressing item.
func (s *s7commReader) parseS7AnyItem(data []byte) (*types.S7CommItem, int) {
	// S7-Any item format (12 bytes):
	// Byte 0: Variable specification (0x12)
	// Byte 1: Length of following address spec (0x0A)
	// Byte 2: Syntax ID (0x10 for S7-Any)
	// Byte 3: Transport size
	// Bytes 4-5: Length (number of items)
	// Bytes 6-7: DB number
	// Byte 8: Memory area
	// Bytes 9-11: Start address (bit address = byte*8 + bit)

	if len(data) < 12 {
		return nil, 0
	}

	varSpec := int(data[0])
	if varSpec != S7VarSpecTypeItem {
		return nil, 1
	}

	addrSpecLen := int(data[1])
	if addrSpecLen != 0x0A {
		// Non-standard item, skip it
		return nil, 2 + addrSpecLen
	}

	item := &types.S7CommItem{
		VariableType:      int32(varSpec),
		SyntaxId:          int32(data[2]),
		TransportSize:     int32(data[3]),
		TransportSizeName: getTransportSizeName(int(data[3])),
		Length:            int32(binary.BigEndian.Uint16(data[4:6])),
		DBNumber:          int32(binary.BigEndian.Uint16(data[6:8])),
		Area:              int32(data[8]),
		AreaName:          getAreaName(int(data[8])),
	}

	// Parse 3-byte address (bit address)
	address := int32(data[9])<<16 | int32(data[10])<<8 | int32(data[11])
	item.Address = address

	return item, 12
}

// parseDownloadUpload parses Download/Upload block parameters.
func (s *s7commReader) parseDownloadUpload(msg *types.S7Comm, data []byte) {
	// These functions have various formats depending on the specific operation
	// Mark as critical since they modify PLC program
	msg.IsCriticalOperation = true

	if len(data) >= 2 {
		msg.SubFunction = int32(data[1])
	}
}

// parsePIService parses PI (Program Invocation) Service parameters.
// PI services carry CPU state-change operations (cold/warm/hot restart), which
// are security-critical per CISA AA26-231A (Modify Controller Tasking / CPU state change).
func (s *s7commReader) parsePIService(msg *types.S7Comm, data []byte) {
	// PI Service is used for PLC control operations like start/stop/reset
	msg.IsCriticalOperation = true
	msg.IsSecurityRelevant = true

	// PI service format varies, basic parsing
	if len(data) >= 2 {
		msg.SubFunction = int32(data[1])
	}

	// Attempt to extract the PI service name string, which identifies the
	// specific control operation (e.g. restart type). The service name is an
	// ASCII string embedded in the parameter block. We scan for a known token.
	svc := extractPIServiceName(data)
	if svc != "" {
		msg.SubFunctionName = getPIServiceName(svc)
	}
}

// extractPIServiceName scans the PI service parameter block for a printable
// ASCII service token (e.g. "P_PROGRAM", "_INSE", "_MODU").
func extractPIServiceName(data []byte) string {
	// Collect the longest run of printable characters; PI service names are
	// short uppercase/underscore tokens.
	best := make([]byte, 0, 16)
	cur := make([]byte, 0, 16)
	for _, b := range data {
		if b == '_' || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') {
			cur = append(cur, b)
			if len(cur) > len(best) {
				best = append(best[:0], cur...)
			}
		} else {
			cur = cur[:0]
		}
	}
	if len(best) < 4 {
		return ""
	}
	return string(best)
}

// getPIServiceName maps a PI service token to a human-readable restart/control name.
func getPIServiceName(svc string) string {
	switch svc {
	case S7PIServiceColdRestart:
		return "Cold Restart (P_PROGRAM)"
	case S7PIServiceWarmRestart:
		return "Warm Restart (_INSE)"
	case S7PIServiceHotRestart:
		return "Hot Restart (_MODU)"
	default:
		return "PI Service: " + svc
	}
}

// parseUserData parses UserData function parameters.
func (s *s7commReader) parseUserData(msg *types.S7Comm, data []byte) {
	// UserData header format:
	// Bytes 0-2: Parameter head (3 bytes)
	// Byte 3: Parameter length
	// Byte 4: Method (request/response)
	// Byte 5: Type + Function group
	// Byte 6: Subfunction
	// Byte 7: Sequence number

	if len(data) < 8 {
		return
	}

	// Skip parameter head
	offset := 4

	if offset < len(data) {
		msg.UserDataMethodType = int32(data[offset])
		offset++
	}

	var funcGroup int
	if offset < len(data) {
		typeFG := data[offset]
		funcGroup = int(typeFG & 0x0F)
		msg.UserDataFunctionGroup = int32(funcGroup)
		msg.UserDataFunctionGroupName = getUserDataFunctionGroupName(funcGroup)
		offset++
	}

	var subFunc int
	if offset < len(data) {
		subFunc = int(data[offset])
		msg.UserDataSubFunction = int32(subFunc)
		offset++
	}

	if offset < len(data) {
		msg.UserDataSequenceNumber = int32(data[offset])
	}

	// Enhanced parsing based on function group
	switch funcGroup {
	case S7UserDataFGSecurity:
		msg.IsSecurityRelevant = true
	case S7UserDataFGBlock:
		msg.IsCriticalOperation = true
		msg.SubFunctionName = getBlockSubfunctionName(subFunc)
	case S7UserDataFGCPUFunc:
		// CPU Functions - includes SZL, diagnostics, alarms
		msg.SubFunctionName = getCPUSubfunctionName(subFunc)
		if subFunc == S7UserDataCPUReadSZL {
			// Mark as security-relevant as it exposes PLC configuration
			msg.IsSecurityRelevant = true
		}
	case S7UserDataFGTime:
		// Time functions
		msg.SubFunctionName = getTimeSubfunctionName(subFunc)
		if subFunc == S7UserDataTimeSet || subFunc == S7UserDataTimeSet2 {
			msg.IsCriticalOperation = true // Setting time can affect PLC operation
		}
	case S7UserDataFGCyclic:
		// Cyclic data (subscriptions)
		msg.SubFunctionName = getCyclicSubfunctionName(subFunc)
	case S7UserDataFGNCProgram:
		// NC Programming (Sinumerik)
		msg.IsCriticalOperation = true
		msg.IsSecurityRelevant = true
	}
}

// getBlockSubfunctionName returns the name for a Block function subfunction.
func getBlockSubfunctionName(subFunc int) string {
	switch subFunc {
	case 0x01:
		return "List Blocks"
	case 0x02:
		return "List Blocks of Type"
	case 0x03:
		return "Get Block Info"
	default:
		return "Unknown"
	}
}

// parseS7Data parses the S7comm data section.
func (s *s7commReader) parseS7Data(msg *types.S7Comm, data []byte) {
	if len(data) < 4 {
		return
	}

	// For Read/Write responses, parse data items
	if msg.FunctionCode == S7FuncReadVar || msg.FunctionCode == S7FuncWriteVar {
		s.parseDataItems(msg, data)
		return
	}

	// For UserData messages, check for SZL response
	if msg.MessageType == S7CommMsgTypeUserData {
		s.parseUserDataData(msg, data)
	}
}

// parseUserDataData parses the data section of UserData messages.
func (s *s7commReader) parseUserDataData(msg *types.S7Comm, data []byte) {
	if len(data) < 4 {
		return
	}

	// UserData data section format:
	// Byte 0: Return code
	// Byte 1: Transport size
	// Bytes 2-3: Data length

	returnCode := int(data[0])
	if returnCode != S7ReturnCodeSuccess {
		return
	}

	// For CPU Functions with Read SZL, parse SZL response
	if msg.UserDataFunctionGroup == S7UserDataFGCPUFunc &&
		msg.UserDataSubFunction == S7UserDataCPUReadSZL {
		s.parseSZLResponse(msg, data)
	}
}

// parseSZLResponse parses an SZL (System Status List) response.
func (s *s7commReader) parseSZLResponse(msg *types.S7Comm, data []byte) {
	// SZL response format:
	// Bytes 0-3: Standard data header
	// Bytes 4-5: SZL-ID
	// Bytes 6-7: SZL-Index
	// Following: SZL data records

	if len(data) < 8 {
		return
	}

	szlID := int(binary.BigEndian.Uint16(data[4:6]))
	// szlIndex := int(binary.BigEndian.Uint16(data[6:8]))

	// Extract meaningful information based on SZL ID
	switch szlID {
	case SZLIDModuleID, SZLIDCPUType, SZLIDComponentID:
		// These SZLs contain text information about the PLC
		s.parseSZLModuleInfo(msg, data[8:], szlID)
	case SZLIDCPUStatus:
		// CPU operating status
		s.parseSZLCPUStatus(msg, data[8:])
	}

	s7commLog.Debug("SZL response parsed",
		zap.Int("szlID", szlID),
		zap.String("szlName", getSZLIDName(szlID)),
	)
}

// parseSZLModuleInfo extracts module/CPU identification from SZL data.
func (s *s7commReader) parseSZLModuleInfo(msg *types.S7Comm, data []byte, szlID int) {
	// SZL record format depends on the specific SZL ID
	// Common format for module identification:
	// Bytes 0-1: Record length
	// Bytes 2-3: Record count
	// Following: Records with text fields

	if len(data) < 4 {
		return
	}

	recordLen := int(binary.BigEndian.Uint16(data[0:2]))
	if recordLen == 0 || len(data) < 4+recordLen {
		return
	}

	// Try to extract text from the record
	recordData := data[4:]
	if len(recordData) >= recordLen {
		// Look for null-terminated strings in the record
		for i := 0; i < len(recordData) && i < recordLen; i++ {
			if recordData[i] == 0 {
				if i > 0 {
					text := string(recordData[:i])
					// Clean up the text (remove non-printable characters)
					cleanText := cleanString(text)
					if len(cleanText) > 0 {
						switch szlID {
						case SZLIDModuleID:
							if msg.ModuleTypeName == "" {
								msg.ModuleTypeName = cleanText
							}
						case SZLIDCPUType:
							if msg.CPUType == "" {
								msg.CPUType = cleanText
							}
						case SZLIDComponentID:
							if msg.PlantIdentification == "" {
								msg.PlantIdentification = cleanText
							}
						}
					}
				}
				break
			}
		}
	}
}

// parseSZLCPUStatus extracts CPU status information.
func (s *s7commReader) parseSZLCPUStatus(msg *types.S7Comm, data []byte) {
	// CPU status SZL contains information about operating mode
	// This is security-relevant as it shows if PLC is running, stopped, etc.
	if len(data) < 4 {
		return
	}

	// Mark as security-relevant since it exposes operational state
	msg.IsSecurityRelevant = true
}

// cleanString removes non-printable characters from a string.
func cleanString(s string) string {
	result := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] >= 32 && s[i] < 127 {
			result = append(result, s[i])
		}
	}
	return string(result)
}

// parseDataItems parses the data items in a Read/Write response.
func (s *s7commReader) parseDataItems(msg *types.S7Comm, data []byte) {
	// Data item format (for each item):
	// Byte 0: Return code (0xFF = success)
	// Byte 1: Transport size
	// Bytes 2-3: Length (in bits or bytes depending on transport size)
	// Following: Data (length depends on transport size)

	offset := 0
	items := make([]*types.S7CommDataItem, 0)

	for offset < len(data)-4 {
		if offset+4 > len(data) {
			break
		}

		returnCode := int(data[offset])
		transportSize := int(data[offset+1])
		length := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))

		item := &types.S7CommDataItem{
			ReturnCode:     int32(returnCode),
			ReturnCodeName: getReturnCodeName(returnCode),
			TransportSize:  int32(transportSize),
			Length:         int32(length),
		}

		offset += 4

		// Calculate data length in bytes
		dataLen := length
		if transportSize == 0x03 || transportSize == 0x04 {
			// Bit or bit-string: length is in bits
			dataLen = (length + 7) / 8
		}

		// Cap data length to prevent buffer overrun
		if offset+dataLen > len(data) {
			dataLen = len(data) - offset
		}

		if dataLen > 0 {
			item.Data = data[offset : offset+dataLen]
			offset += dataLen
		}

		// Align to word boundary for next item
		if offset%2 != 0 && returnCode == S7ReturnCodeSuccess {
			offset++
		}

		items = append(items, item)
	}

	msg.DataItems = items
}
