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

package dnp3

import (
	"bytes"
	"encoding/binary"
	"sync/atomic"

	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/decoder/core"
	"github.com/dreadl0ck/netcap/types"
)

// DNP3 Function Codes
const (
	FuncConfirm              = 0x00
	FuncRead                 = 0x01
	FuncWrite                = 0x02
	FuncSelect               = 0x03
	FuncOperate              = 0x04
	FuncDirectOperate        = 0x05
	FuncDirectOperateNoAck   = 0x06
	FuncImmediateFreeze      = 0x07
	FuncImmediateFreezeNoAck = 0x08
	FuncFreezeAndClear       = 0x09
	FuncFreezeAndClearNoAck  = 0x0A
	FuncFreezeAtTime         = 0x0B
	FuncFreezeAtTimeNoAck    = 0x0C
	FuncColdRestart          = 0x0D
	FuncWarmRestart          = 0x0E
	FuncInitData             = 0x0F
	FuncInitApplication      = 0x10
	FuncStartApplication     = 0x11
	FuncStopApplication      = 0x12
	FuncSaveConfiguration    = 0x13
	FuncEnableUnsolicited    = 0x14
	FuncDisableUnsolicited   = 0x15
	FuncAssignClass          = 0x16
	FuncDelayMeasurement     = 0x17
	FuncRecordCurrentTime    = 0x18
	FuncOpenFile             = 0x19
	FuncCloseFile            = 0x1A
	FuncDeleteFile           = 0x1B
	FuncGetFileInfo          = 0x1C
	FuncAuthenticate         = 0x1D
	FuncAbortFile            = 0x1E
	FuncResponse             = 0x81
	FuncUnsolicitedResponse  = 0x82
)

// Critical function codes that could affect physical processes
var criticalFunctions = map[uint8]bool{
	FuncOperate:              true,
	FuncDirectOperate:        true,
	FuncDirectOperateNoAck:   true,
	FuncColdRestart:          true,
	FuncWarmRestart:          true,
	FuncInitData:             true,
	FuncInitApplication:      true,
	FuncStartApplication:     true,
	FuncStopApplication:      true,
	FuncImmediateFreeze:      true,
	FuncImmediateFreezeNoAck: true,
	FuncFreezeAndClear:       true,
	FuncFreezeAndClearNoAck:  true,
}

// Config change functions
var configChangeFunctions = map[uint8]bool{
	FuncWrite:              true,
	FuncSaveConfiguration:  true,
	FuncAssignClass:        true,
	FuncEnableUnsolicited:  true,
	FuncDisableUnsolicited: true,
}

type dnp3Reader struct {
	conversation *core.ConversationInfo
}

// New returns a new DNP3 reader.
func (d *dnp3Reader) New(conversation *core.ConversationInfo) core.StreamDecoderInterface {
	return &dnp3Reader{
		conversation: conversation,
	}
}

// Decode parses DNP3 messages from the stream.
func (d *dnp3Reader) Decode() {
	if Decoder.Writer == nil {
		dnp3Log.Error("DNP3 Decoder.Writer is nil")
		return
	}

	var buf bytes.Buffer

	for _, data := range d.conversation.Data {
		buf.Write(data.Raw())
	}

	frameData := buf.Bytes()
	offset := 0

	for offset < len(frameData)-10 {
		// Look for DNP3 start bytes
		if frameData[offset] != dnp3StartByte1 || frameData[offset+1] != dnp3StartByte2 {
			offset++
			continue
		}

		msg := d.parseDNP3Frame(frameData[offset:])
		if msg != nil {
			msg.SrcIP = d.conversation.ClientIP
			msg.DstIP = d.conversation.ServerIP
			msg.SrcPort = int32(d.conversation.ClientPort)
			msg.DstPort = int32(d.conversation.ServerPort)
			msg.CommunityID = d.conversation.CommunityID

			err := Decoder.Writer.Write(msg)
			if err != nil {
				dnp3Log.Error("failed to write DNP3 record", zap.Error(err))
			} else {
				atomic.AddInt64(&Decoder.NumRecordsWritten, 1)
			}
		}

		// Move to next frame (minimum frame is 10 bytes)
		frameLen := 10
		if offset+2 < len(frameData) {
			frameLen = int(frameData[offset+2]) + 5 // Length field + header overhead
		}
		offset += frameLen
	}
}

func (d *dnp3Reader) parseDNP3Frame(data []byte) *types.DNP3 {
	if len(data) < 10 {
		return nil
	}

	// Validate start bytes
	if data[0] != dnp3StartByte1 || data[1] != dnp3StartByte2 {
		return nil
	}

	msg := &types.DNP3{
		Timestamp: d.conversation.FirstClientPacket.UnixNano(),
	}

	// Data Link Layer Header (IEEE 1815)
	// Byte 0-1: Start bytes (0x0564)
	// Byte 2: Length (number of user data octets including CRCs)
	// Byte 3: Control
	// Byte 4-5: Destination (little-endian)
	// Byte 6-7: Source (little-endian)
	// Byte 8-9: CRC of header
	msg.Length = int32(data[2])
	msg.Control = int32(data[3])

	// Parse control byte per IEEE 1815
	msg.IsMaster = (data[3] & 0x80) != 0  // DIR bit: 1=Master, 0=Outstation
	msg.IsRequest = (data[3] & 0x40) != 0 // PRM bit: 1=Primary (request), 0=Secondary (response)

	// Destination and Source addresses (little-endian, 16-bit)
	msg.Destination = int32(binary.LittleEndian.Uint16(data[4:6]))
	msg.Source = int32(binary.LittleEndian.Uint16(data[6:8]))

	// CRC is at bytes 8-9 - validate if possible
	// Header CRC covers bytes 0-7
	headerCRC := binary.LittleEndian.Uint16(data[8:10])
	if headerCRC == 0 && msg.Length > 0 {
		// Suspicious: zero CRC with data usually indicates corruption
		dnp3Log.Debug("DNP3 header CRC is zero, potentially corrupted frame")
	}

	// If there's application layer data (length > 5 means user data present)
	// Length field counts bytes after the header, minus 5 for the header fields
	if msg.Length > 5 && len(data) > 10 {
		// Extract user data, removing per-block CRCs
		// DNP3 data is in 16-byte blocks, each followed by 2-byte CRC
		userData := d.extractUserData(data[10:], int(msg.Length)-5)
		if len(userData) > 0 {
			d.parseApplicationLayer(msg, userData)
		}
	}

	return msg
}

// extractUserData removes the CRC bytes from DNP3 data blocks
// DNP3 uses 16-byte blocks, each followed by a 2-byte CRC
func (d *dnp3Reader) extractUserData(data []byte, expectedLen int) []byte {
	if len(data) == 0 {
		return nil
	}

	var result []byte
	offset := 0
	remaining := expectedLen

	for offset < len(data) && remaining > 0 {
		// Each block is max 16 bytes of data + 2 bytes CRC
		blockDataLen := 16
		if remaining < 16 {
			blockDataLen = remaining
		}

		if offset+blockDataLen+2 > len(data) {
			// Not enough data for block + CRC, take what we can
			if offset+blockDataLen <= len(data) {
				result = append(result, data[offset:offset+blockDataLen]...)
			}
			break
		}

		result = append(result, data[offset:offset+blockDataLen]...)
		offset += blockDataLen + 2 // Skip the 2-byte CRC
		remaining -= blockDataLen
	}

	return result
}

func (d *dnp3Reader) parseApplicationLayer(msg *types.DNP3, data []byte) {
	if len(data) < 2 {
		return
	}

	// Transport Layer (1 byte)
	transportByte := data[0]
	msg.TransportSeq = int32(transportByte & 0x3F)
	msg.TransportFIN = (transportByte & 0x80) != 0
	msg.TransportFIR = (transportByte & 0x40) != 0

	if len(data) < 3 {
		return
	}

	// Application Layer Control (1 byte)
	appControl := data[1]
	msg.ApplicationControl = int32(appControl)
	msg.ApplicationSeq = int32(appControl & 0x0F)
	msg.ConfirmRequired = (appControl & 0x20) != 0
	msg.Unsolicited = (appControl & 0x10) != 0

	// Function Code (1 byte)
	funcCode := data[2]
	msg.FunctionCode = int32(funcCode)
	msg.FunctionCodeName = getFunctionCodeName(funcCode)

	// Set security-relevant flags
	msg.IsCriticalFunction = criticalFunctions[funcCode]
	msg.IsConfigChange = configChangeFunctions[funcCode]
	msg.IsAuthentication = funcCode == FuncAuthenticate

	// Parse Internal Indications for response messages
	if funcCode == FuncResponse || funcCode == FuncUnsolicitedResponse {
		if len(data) >= 5 {
			iin := binary.LittleEndian.Uint16(data[3:5])
			msg.InternalIndications = int32(iin)
			d.parseIIN(msg, iin)
		}
	}

	// Parse objects if present
	objOffset := 3
	if funcCode == FuncResponse || funcCode == FuncUnsolicitedResponse {
		objOffset = 5 // Skip IIN bytes
	}

	if len(data) > objOffset {
		d.parseObjects(msg, data[objOffset:])
	}
}

func (d *dnp3Reader) parseIIN(msg *types.DNP3, iin uint16) {
	// First byte (IIN1)
	msg.IINBroadcast = (iin & 0x0001) != 0
	msg.IINClass1 = (iin & 0x0002) != 0
	msg.IINClass2 = (iin & 0x0004) != 0
	msg.IINClass3 = (iin & 0x0008) != 0
	msg.IINNeedTime = (iin & 0x0010) != 0
	msg.IINLocalControl = (iin & 0x0020) != 0
	msg.IINDeviceTrouble = (iin & 0x0040) != 0
	msg.IINDeviceRestart = (iin & 0x0080) != 0

	// Second byte (IIN2)
	msg.IINNoFuncCodeSupport = (iin & 0x0100) != 0
	msg.IINObjectUnknown = (iin & 0x0200) != 0
	msg.IINParameterError = (iin & 0x0400) != 0
	msg.IINEventBufferOverflow = (iin & 0x0800) != 0
	msg.IINAlreadyExecuting = (iin & 0x1000) != 0
	msg.IINConfigCorrupt = (iin & 0x2000) != 0
}

func (d *dnp3Reader) parseObjects(msg *types.DNP3, data []byte) {
	offset := 0

	for offset < len(data)-3 {
		obj := &types.DNP3Object{
			ObjectGroup: int32(data[offset]),
			Variation:   int32(data[offset+1]),
			ObjectName:  getObjectName(data[offset], data[offset+1]),
		}

		qualifier := data[offset+2]
		obj.Qualifier = int32(qualifier)

		offset += 3

		// Parse range based on qualifier
		switch qualifier & 0x0F {
		case 0x00, 0x01: // Start-Stop (1 or 2 bytes)
			if offset+2 <= len(data) {
				obj.StartIndex = int32(data[offset])
				obj.StopIndex = int32(data[offset+1])
				obj.Count = obj.StopIndex - obj.StartIndex + 1
				offset += 2
			}
		case 0x06: // All objects
			obj.Count = -1 // Indicates all
		case 0x07, 0x08: // Count (1 or 2 bytes)
			if offset+1 <= len(data) {
				obj.Count = int32(data[offset])
				offset++
			}
		}

		msg.Objects = append(msg.Objects, obj)

		// Safety break to prevent infinite loops
		if offset <= 0 {
			break
		}
	}
}

func getFunctionCodeName(code uint8) string {
	switch code {
	case FuncConfirm:
		return "CONFIRM"
	case FuncRead:
		return "READ"
	case FuncWrite:
		return "WRITE"
	case FuncSelect:
		return "SELECT"
	case FuncOperate:
		return "OPERATE"
	case FuncDirectOperate:
		return "DIRECT_OPERATE"
	case FuncDirectOperateNoAck:
		return "DIRECT_OPERATE_NO_ACK"
	case FuncImmediateFreeze:
		return "IMMEDIATE_FREEZE"
	case FuncImmediateFreezeNoAck:
		return "IMMEDIATE_FREEZE_NO_ACK"
	case FuncFreezeAndClear:
		return "FREEZE_AND_CLEAR"
	case FuncFreezeAndClearNoAck:
		return "FREEZE_AND_CLEAR_NO_ACK"
	case FuncColdRestart:
		return "COLD_RESTART"
	case FuncWarmRestart:
		return "WARM_RESTART"
	case FuncInitData:
		return "INITIALIZE_DATA"
	case FuncInitApplication:
		return "INITIALIZE_APPLICATION"
	case FuncStartApplication:
		return "START_APPLICATION"
	case FuncStopApplication:
		return "STOP_APPLICATION"
	case FuncSaveConfiguration:
		return "SAVE_CONFIGURATION"
	case FuncEnableUnsolicited:
		return "ENABLE_UNSOLICITED"
	case FuncDisableUnsolicited:
		return "DISABLE_UNSOLICITED"
	case FuncAssignClass:
		return "ASSIGN_CLASS"
	case FuncDelayMeasurement:
		return "DELAY_MEASUREMENT"
	case FuncRecordCurrentTime:
		return "RECORD_CURRENT_TIME"
	case FuncAuthenticate:
		return "AUTHENTICATE"
	case FuncResponse:
		return "RESPONSE"
	case FuncUnsolicitedResponse:
		return "UNSOLICITED_RESPONSE"
	default:
		return "UNKNOWN"
	}
}

func getObjectName(group, variation uint8) string {
	switch group {
	case 1:
		return "Binary Input"
	case 2:
		return "Binary Input Event"
	case 3:
		return "Double-bit Binary Input"
	case 10:
		return "Binary Output"
	case 12:
		return "Control Relay Output Block (CROB)"
	case 20:
		return "Counter"
	case 21:
		return "Frozen Counter"
	case 30:
		return "Analog Input"
	case 32:
		return "Analog Input Event"
	case 40:
		return "Analog Output Status"
	case 41:
		return "Analog Output Block"
	case 50:
		return "Time and Date"
	case 60:
		return "Class Data"
	case 70:
		return "File Control"
	case 80:
		return "Internal Indications"
	case 110:
		return "Octet String"
	case 120:
		return "Authentication"
	default:
		return "Unknown"
	}
}
