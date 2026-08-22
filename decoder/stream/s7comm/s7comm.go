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
	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/decoder"
	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/core"
	logging "github.com/dreadl0ck/netcap/internal/logger"
	"github.com/dreadl0ck/netcap/types"
)

var s7commLog = zap.NewNop()

const serviceS7Comm = "S7Comm"

// TPKT Header (RFC 1006) - 4 bytes
const (
	tpktVersion     = 0x03 // TPKT version 3
	tpktHeaderSize  = 4    // Version (1) + Reserved (1) + Length (2)
)

// COTP PDU Types (ISO 8073)
// These are the upper nibble values after masking with 0xF0
// The PDU type is encoded in the upper nibble of the COTP header byte
const (
	COTPTypeCR = 0xE0 // Connection Request (type code 14 = 0xE in upper nibble)
	COTPTypeCC = 0xD0 // Connection Confirm (type code 13 = 0xD in upper nibble)
	COTPTypeDR = 0x80 // Disconnect Request (type code 8 = 0x8 in upper nibble)
	COTPTypeDC = 0xC0 // Disconnect Confirm (type code 12 = 0xC in upper nibble)
	COTPTypeDT = 0xF0 // Data Transfer (type code 15 = 0xF in upper nibble)
	COTPTypeED = 0x10 // Expedited Data (type code 1 = 0x1 in upper nibble)
	COTPTypeAK = 0x60 // Data Acknowledgement (type code 6 = 0x6 in upper nibble)
	COTPTypeEA = 0x20 // Expedited Data Acknowledgement (type code 2 = 0x2 in upper nibble)
	COTPTypeRJ = 0x50 // Reject (type code 5 = 0x5 in upper nibble)
	COTPTypeER = 0x70 // TPDU Error (type code 7 = 0x7 in upper nibble)
)

// S7comm Protocol IDs
const (
	s7commProtocolID     = 0x32 // Classic S7Comm (S7-300/400)
	s7commPlusProtocolID = 0x72 // S7Comm Plus (S7-1200/1500, TIA Portal)
)

// S7CommPlus opcodes (cleartext, even when the body is integrity-protected).
const (
	s7PlusOpcodeRequest      = 0x31 // Request
	s7PlusOpcodeResponse     = 0x32 // Response
	s7PlusOpcodeNotification = 0x33 // Notification
)

// S7comm Message Types (ROSCTR - Remote Operating Service Control)
const (
	S7CommMsgTypeJobRequest = 0x01 // Job Request (client -> PLC)
	S7CommMsgTypeAck        = 0x02 // Acknowledgement without data
	S7CommMsgTypeAckData    = 0x03 // Acknowledgement with data
	S7CommMsgTypeUserData   = 0x07 // UserData (e.g., block upload, CPU info)
)

// S7comm Function Codes
const (
	S7FuncCPUServices        = 0x00 // CPU services
	S7FuncSetupCommunication = 0xF0 // Setup communication
	S7FuncReadVar            = 0x04 // Read variable
	S7FuncWriteVar           = 0x05 // Write variable
	S7FuncRequestDownload    = 0x1A // Request download
	S7FuncDownloadBlock      = 0x1B // Download block
	S7FuncDownloadEnded      = 0x1C // Download ended
	S7FuncStartUpload        = 0x1D // Start upload
	S7FuncUpload             = 0x1E // Upload
	S7FuncEndUpload          = 0x1F // End upload
	S7FuncPIService          = 0x28 // PI (Program Invocation) service
	S7FuncPLCStop            = 0x29 // PLC stop
)

// PI (Program Invocation) service names carried in the parameter string.
// These identify CPU state-change operations (cold/warm/hot restart) which
// are security-critical per CISA AA26-231A (Modify Controller Tasking / CPU state change).
const (
	S7PIServiceColdRestart = "P_PROGRAM" // Cold restart
	S7PIServiceWarmRestart = "_INSE"     // Warm restart / insert
	S7PIServiceHotRestart  = "_MODU"     // Hot restart / module
)

// S7comm Variable Specification Types
const (
	S7VarSpecTypeItem = 0x12 // Item specification
)

// S7comm Syntax IDs
const (
	S7SyntaxIDS7Any       = 0x10 // S7-Any pointer (classic addressing)
	S7SyntaxIDDriveESAny  = 0x11 // Drive ES Any
	S7SyntaxID1200Sym     = 0x12 // 1200 symbolic addressing
	S7SyntaxIDDBRead      = 0x13 // DB read (PBC ID)
	S7SyntaxIDNCK         = 0x82 // NCK addressing (Sinumerik)
	S7SyntaxIDDriveMCSync = 0xA2 // Drive motion control sync
)

// S7comm Memory Areas (from Wireshark packet-s7comm.c)
const (
	S7AreaSysInfo       = 0x03 // System info of 200 family
	S7AreaSysFlags      = 0x05 // System flags of 200 family
	S7AreaAnalogInputs  = 0x06 // Analog inputs of 200 family
	S7AreaAnalogOutputs = 0x07 // Analog outputs of 200 family
	S7AreaCounter       = 0x1C // Counter (200 family) / (S7-300/400)
	S7AreaTimer         = 0x1D // Timer (200 family) / (S7-300/400)
	S7AreaCounter200    = 0x1E // Counter (200 family IEC)
	S7AreaTimer200      = 0x1F // Timer (200 family IEC)
	S7AreaPeripheral    = 0x80 // Direct peripheral access (P) - critical for I/O
	S7AreaInputs        = 0x81 // Process inputs (I)
	S7AreaOutputs       = 0x82 // Process outputs (Q)
	S7AreaFlags         = 0x83 // Bit memory/Merker (M)
	S7AreaDB            = 0x84 // Data blocks (DB)
	S7AreaDI            = 0x85 // Instance data blocks (DI)
	S7AreaLocal         = 0x86 // Local data (L)
	S7AreaVMemory       = 0x87 // V-Memory (200 family)
)

// S7comm Transport Sizes (in request)
const (
	S7TransportSizeNull   = 0x00 // NULL
	S7TransportSizeBit    = 0x01 // BIT
	S7TransportSizeByte   = 0x02 // BYTE/CHAR
	S7TransportSizeChar   = 0x03 // CHAR
	S7TransportSizeWord   = 0x04 // WORD
	S7TransportSizeInt    = 0x05 // INT
	S7TransportSizeDWord  = 0x06 // DWORD
	S7TransportSizeDInt   = 0x07 // DINT
	S7TransportSizeReal   = 0x08 // REAL
	S7TransportSizeDate   = 0x09 // DATE
	S7TransportSizeTOD    = 0x0A // TOD (Time of Day)
	S7TransportSizeTime   = 0x0B // TIME
	S7TransportSizeS5Time = 0x0C // S5TIME
	S7TransportSizeDT     = 0x0F // DATE_AND_TIME
	S7TransportSizeCounter = 0x1C // COUNTER
	S7TransportSizeTimer  = 0x1D // TIMER
	S7TransportSizeIECCounter = 0x1E // IEC COUNTER (200 family)
	S7TransportSizeIECTimer = 0x1F // IEC TIMER (200 family)
	S7TransportSizeHSCounter = 0x20 // HS COUNTER (200 family)
)

// S7comm Return Codes
const (
	S7ReturnCodeReserved           = 0x00 // Reserved
	S7ReturnCodeHardwareError      = 0x01 // Hardware error
	S7ReturnCodeAccessingObject    = 0x03 // Accessing the object not allowed
	S7ReturnCodeAddressOutOfRange  = 0x05 // Address out of range
	S7ReturnCodeDataTypeNotSupported = 0x06 // Data type not supported
	S7ReturnCodeDataTypeInconsistent = 0x07 // Data type inconsistent
	S7ReturnCodeObjectNotExists    = 0x0A // Object does not exist
	S7ReturnCodeSuccess            = 0xFF // Success
)

// UserData function groups (from Wireshark packet-s7comm.h)
const (
	S7UserDataFGProgram     = 0x01 // Programmer commands
	S7UserDataFGCyclic      = 0x02 // Cyclic data
	S7UserDataFGBlock       = 0x03 // Block functions
	S7UserDataFGCPUFunc     = 0x04 // CPU functions
	S7UserDataFGSecurity    = 0x05 // Security
	S7UserDataFGPBCBSend    = 0x06 // PBC BSEND/BRECV
	S7UserDataFGTime        = 0x07 // Time functions
	S7UserDataFGNCProgram   = 0x0F // NC Programming (Sinumerik)
)

// UserData subfunctions for CPU Functions (0x04)
const (
	S7UserDataCPUReadSZL      = 0x01 // Read SZL (System Status List)
	S7UserDataCPUMsgService   = 0x02 // Message service
	S7UserDataCPUDiagMessage  = 0x03 // Diagnostic message
	S7UserDataCPUAlarmQuery   = 0x13 // Alarm query
)

// UserData subfunctions for Time Functions (0x07)
const (
	S7UserDataTimeRead  = 0x01 // Read clock
	S7UserDataTimeSet   = 0x02 // Set clock
	S7UserDataTimeReadF = 0x03 // Read clock (F)
	S7UserDataTimeSet2  = 0x04 // Set clock
)

// UserData subfunctions for Cyclic Data (0x02)
const (
	S7UserDataCyclicMem      = 0x01 // Memory
	S7UserDataCyclicUnsubscr = 0x04 // Unsubscribe
)

// SZL ID classes (System Status List - from packet-s7comm_szl_ids.h)
const (
	SZLIDModuleID        = 0x0011 // Module identification
	SZLIDCPUCharacter    = 0x0012 // CPU characteristics
	SZLIDMemoryAreas     = 0x0013 // Memory areas
	SZLIDSystemAreas     = 0x0014 // System areas
	SZLIDBlockTypes      = 0x0015 // Block types
	SZLIDCPUType         = 0x001C // CPU type
	SZLIDComponentID     = 0x001D // Component identification
	SZLIDInterruptStatus = 0x0022 // Interrupt status
	SZLIDAssignmentList  = 0x0025 // Assignment list
	SZLIDCPUStatus       = 0x0074 // CPU status
	SZLIDModeTransition  = 0x0090 // Mode transition
	SZLIDStartupInfo     = 0x0094 // Startup information
	SZLIDCommunication   = 0x0111 // Communication status
	SZLIDLEDStatus       = 0x0019 // LED status
	SZLIDRackStation     = 0x0091 // Rack/station status
	SZLIDDiagBuffer      = 0x00A0 // Diagnostic buffer
)

// Block types for block services
const (
	S7BlockTypeOB  = 0x08 // Organization Block
	S7BlockTypeDB  = 0x0A // Data Block
	S7BlockTypeSDB = 0x0B // System Data Block
	S7BlockTypeFC  = 0x0C // Function
	S7BlockTypeSFC = 0x0D // System Function
	S7BlockTypeFB  = 0x0E // Function Block
	S7BlockTypeSFB = 0x0F // System Function Block
)

// Alarm types
const (
	S7AlarmTypeScan      = 0x01 // Scan alarm
	S7AlarmTypeAlarm8    = 0x02 // Alarm_8
	S7AlarmTypeAlarm8P   = 0x04 // Alarm_8P
	S7AlarmTypeNotify    = 0x05 // Notify
	S7AlarmTypeAlarmS    = 0x06 // Alarm_S (SQ)
	S7AlarmTypeAlarmSQ   = 0x07 // Alarm_SQ
	S7AlarmTypeAlarm     = 0x08 // Alarm
	S7AlarmTypeAlarmAck  = 0x09 // Alarm Ack
	S7AlarmTypeAlarmLock = 0x0A // Alarm Lock
)

// Minimum header sizes
const (
	minTPKTSize    = 4  // TPKT header size
	minCOTPDTSize  = 3  // Minimum COTP DT header (length + PDU type + TPDU number)
	minCOTPCRSize  = 7  // Minimum COTP CR/CC header
	minS7CommSize  = 10 // S7comm header for Job/Ack-Data
)

// Decoder for protocol analysis and writing audit records to disk.
var Decoder = &decoder.StreamDecoder{
	Type:        types.Type_NC_S7Comm,
	Name:        serviceS7Comm,
	Description: "Siemens S7 Communication Protocol for ICS/SCADA PLC communication",
	PostInit: func(d *decoder.StreamDecoder) error {
		var err error
		s7commLog, _, err = logging.InitZapLogger(
			decoderconfig.Instance.Out,
			"s7comm",
			decoderconfig.Instance.Debug,
		)
		return err
	},
	CanDecode: func(client, server []byte) bool {
		// S7comm is encapsulated in TPKT (RFC 1006) on TCP port 102
		// Check for TPKT header signature
		return canDecodeS7Comm(client) || canDecodeS7Comm(server)
	},
	DeInit: func(sd *decoder.StreamDecoder) error {
		return s7commLog.Sync()
	},
	Factory: &s7commReader{},
	Typ:     core.TCP, // S7comm uses TCP port 102
}

// canDecodeS7Comm checks if the data looks like a TPKT/COTP/S7comm message.
// S7comm is encapsulated in TPKT (RFC 1006) and COTP (ISO 8073).
func canDecodeS7Comm(data []byte) bool {
	if len(data) < minTPKTSize+minCOTPDTSize {
		return false
	}

	// Check TPKT header
	// Byte 0: Version (must be 3)
	// Byte 1: Reserved (typically 0)
	// Bytes 2-3: Length (big-endian, must be at least 7 for minimal valid message)
	if data[0] != tpktVersion {
		return false
	}

	// Reserved byte should be 0
	if data[1] != 0x00 {
		return false
	}

	// Get TPKT length (big-endian)
	tpktLength := int(data[2])<<8 | int(data[3])
	if tpktLength < minTPKTSize+minCOTPDTSize || tpktLength > 65535 {
		return false
	}

	// Check that we have enough data
	if len(data) < tpktLength {
		// Partial message is still potentially valid
		if len(data) < minTPKTSize+minCOTPDTSize+minS7CommSize {
			return false
		}
	}

	// Parse COTP header
	cotpOffset := minTPKTSize
	cotpLength := int(data[cotpOffset])
	if cotpLength < 2 {
		return false
	}

	cotpPDUType := data[cotpOffset+1] & 0xF0 // Upper nibble is PDU type

	// Validate COTP PDU type
	switch cotpPDUType {
	case COTPTypeCR, COTPTypeCC, COTPTypeDR, COTPTypeDC, COTPTypeDT, COTPTypeER:
		// Valid PDU types for S7comm
	default:
		return false
	}

	// For Data Transfer (DT), check for S7comm payload
	if cotpPDUType == COTPTypeDT {
		// DT header is minimal, just check for S7comm protocol ID
		s7commOffset := cotpOffset + 1 + cotpLength
		if s7commOffset >= len(data) {
			// No S7comm payload, but TPKT/COTP is valid
			// Could be a COTP-only message
			return true
		}

		// Check S7comm protocol ID (0x32 for classic, 0x72 for S7Comm Plus)
		protocolID := data[s7commOffset]
		if protocolID != s7commProtocolID && protocolID != s7commPlusProtocolID {
			return false
		}

		// For classic S7Comm, validate message type
		if protocolID == s7commProtocolID && s7commOffset+1 < len(data) {
			msgType := data[s7commOffset+1]
			switch msgType {
			case S7CommMsgTypeJobRequest, S7CommMsgTypeAck, S7CommMsgTypeAckData, S7CommMsgTypeUserData:
				// Valid message type
			default:
				return false
			}
		}
		// S7Comm Plus (0x72) has different structure, accept it if protocol ID matches
	}

	return true
}

// isS7CommPlus checks if this is an S7Comm Plus (TIA Portal) message
func isS7CommPlus(protocolID byte) bool {
	return protocolID == s7commPlusProtocolID
}

// getCOTPPDUTypeName returns the human-readable name for a COTP PDU type.
func getCOTPPDUTypeName(pduType int) string {
	switch pduType & 0xF0 {
	case COTPTypeCR:
		return "CR (Connection Request)"
	case COTPTypeCC:
		return "CC (Connection Confirm)"
	case COTPTypeDR:
		return "DR (Disconnect Request)"
	case COTPTypeDC:
		return "DC (Disconnect Confirm)"
	case COTPTypeDT:
		return "DT (Data)"
	case COTPTypeED:
		return "ED (Expedited Data)"
	case COTPTypeAK:
		return "AK (Data Acknowledgement)"
	case COTPTypeEA:
		return "EA (Expedited Data Acknowledgement)"
	case COTPTypeRJ:
		return "RJ (Reject)"
	case COTPTypeER:
		return "ER (TPDU Error)"
	default:
		return "Unknown"
	}
}

// getMessageTypeName returns the human-readable name for an S7comm message type.
func getMessageTypeName(msgType int) string {
	switch msgType {
	case S7CommMsgTypeJobRequest:
		return "Job Request"
	case S7CommMsgTypeAck:
		return "Ack"
	case S7CommMsgTypeAckData:
		return "Ack-Data"
	case S7CommMsgTypeUserData:
		return "UserData"
	default:
		return "Unknown"
	}
}

// getFunctionName returns the human-readable name for an S7comm function code.
func getFunctionName(funcCode int) string {
	switch funcCode {
	case S7FuncCPUServices:
		return "CPU Services"
	case S7FuncSetupCommunication:
		return "Setup Communication"
	case S7FuncReadVar:
		return "Read Var"
	case S7FuncWriteVar:
		return "Write Var"
	case S7FuncRequestDownload:
		return "Request Download"
	case S7FuncDownloadBlock:
		return "Download Block"
	case S7FuncDownloadEnded:
		return "Download Ended"
	case S7FuncStartUpload:
		return "Start Upload"
	case S7FuncUpload:
		return "Upload"
	case S7FuncEndUpload:
		return "End Upload"
	case S7FuncPIService:
		return "PI Service"
	case S7FuncPLCStop:
		return "PLC Stop"
	default:
		return "Unknown"
	}
}

// getAreaName returns the human-readable name for an S7comm memory area.
func getAreaName(area int) string {
	switch area {
	case S7AreaSysInfo:
		return "SysInfo"
	case S7AreaSysFlags:
		return "SysFlags"
	case S7AreaAnalogInputs:
		return "AnalogInputs"
	case S7AreaAnalogOutputs:
		return "AnalogOutputs"
	case S7AreaCounter:
		return "Counter"
	case S7AreaTimer:
		return "Timer"
	case S7AreaCounter200:
		return "Counter200"
	case S7AreaTimer200:
		return "Timer200"
	case S7AreaPeripheral:
		return "Peripheral (P)"
	case S7AreaInputs:
		return "Inputs (I)"
	case S7AreaOutputs:
		return "Outputs (Q)"
	case S7AreaFlags:
		return "Flags/Merker (M)"
	case S7AreaDB:
		return "DataBlock (DB)"
	case S7AreaDI:
		return "InstanceDB (DI)"
	case S7AreaLocal:
		return "Local (L)"
	case S7AreaVMemory:
		return "V-Memory"
	default:
		return "Unknown"
	}
}

// getTransportSizeName returns the human-readable name for an S7comm transport size.
func getTransportSizeName(size int) string {
	switch size {
	case S7TransportSizeNull:
		return "NULL"
	case S7TransportSizeBit:
		return "BIT"
	case S7TransportSizeByte:
		return "BYTE"
	case S7TransportSizeChar:
		return "CHAR"
	case S7TransportSizeWord:
		return "WORD"
	case S7TransportSizeInt:
		return "INT"
	case S7TransportSizeDWord:
		return "DWORD"
	case S7TransportSizeDInt:
		return "DINT"
	case S7TransportSizeReal:
		return "REAL"
	case S7TransportSizeDate:
		return "DATE"
	case S7TransportSizeTOD:
		return "TOD"
	case S7TransportSizeTime:
		return "TIME"
	case S7TransportSizeS5Time:
		return "S5TIME"
	case S7TransportSizeDT:
		return "DATE_AND_TIME"
	case S7TransportSizeCounter:
		return "COUNTER"
	case S7TransportSizeTimer:
		return "TIMER"
	case S7TransportSizeIECCounter:
		return "IEC_COUNTER"
	case S7TransportSizeIECTimer:
		return "IEC_TIMER"
	case S7TransportSizeHSCounter:
		return "HS_COUNTER"
	default:
		return "Unknown"
	}
}

// getReturnCodeName returns the human-readable name for an S7comm return code.
func getReturnCodeName(code int) string {
	switch code {
	case S7ReturnCodeReserved:
		return "Reserved"
	case S7ReturnCodeHardwareError:
		return "Hardware Error"
	case S7ReturnCodeAccessingObject:
		return "Access Denied"
	case S7ReturnCodeAddressOutOfRange:
		return "Address Out of Range"
	case S7ReturnCodeDataTypeNotSupported:
		return "Data Type Not Supported"
	case S7ReturnCodeDataTypeInconsistent:
		return "Data Type Inconsistent"
	case S7ReturnCodeObjectNotExists:
		return "Object Does Not Exist"
	case S7ReturnCodeSuccess:
		return "Success"
	default:
		return "Unknown"
	}
}

// getUserDataFunctionGroupName returns the human-readable name for a UserData function group.
func getUserDataFunctionGroupName(fg int) string {
	switch fg {
	case S7UserDataFGProgram:
		return "Programmer Commands"
	case S7UserDataFGCyclic:
		return "Cyclic Data"
	case S7UserDataFGBlock:
		return "Block Functions"
	case S7UserDataFGCPUFunc:
		return "CPU Functions"
	case S7UserDataFGSecurity:
		return "Security"
	case S7UserDataFGPBCBSend:
		return "PBC BSEND/BRECV"
	case S7UserDataFGTime:
		return "Time Functions"
	case S7UserDataFGNCProgram:
		return "NC Programming"
	default:
		return "Unknown"
	}
}

// getErrorName returns the human-readable name for an S7comm error.
func getErrorName(errorClass, errorCode int) string {
	switch errorClass {
	case 0x00:
		return "No error"
	case 0x81:
		switch errorCode {
		case 0x01:
			return "Application relationship error"
		case 0x02:
			return "Object definition error"
		case 0x03:
			return "No resources available"
		case 0x04:
			return "Service not implemented"
		case 0x05:
			return "Invalid addressing"
		case 0x06:
			return "Data type not supported"
		case 0x07:
			return "Data type inconsistent"
		case 0x0A:
			return "Object does not exist"
		default:
			return "Application error"
		}
	case 0x82:
		return "Object resource error"
	case 0x83:
		return "Service processing error"
	case 0x84:
		return "External resource error"
	case 0x85:
		return "Application error"
	case 0x87:
		return "Request error"
	default:
		return "Unknown error"
	}
}

// getSZLIDName returns the human-readable name for an SZL ID.
func getSZLIDName(szlID int) string {
	switch szlID {
	case SZLIDModuleID:
		return "Module Identification"
	case SZLIDCPUCharacter:
		return "CPU Characteristics"
	case SZLIDMemoryAreas:
		return "Memory Areas"
	case SZLIDSystemAreas:
		return "System Areas"
	case SZLIDBlockTypes:
		return "Block Types"
	case SZLIDCPUType:
		return "CPU Type"
	case SZLIDComponentID:
		return "Component Identification"
	case SZLIDInterruptStatus:
		return "Interrupt Status"
	case SZLIDAssignmentList:
		return "Assignment List"
	case SZLIDCPUStatus:
		return "CPU Status"
	case SZLIDModeTransition:
		return "Mode Transition"
	case SZLIDStartupInfo:
		return "Startup Information"
	case SZLIDCommunication:
		return "Communication Status"
	case SZLIDLEDStatus:
		return "LED Status"
	case SZLIDRackStation:
		return "Rack/Station Status"
	case SZLIDDiagBuffer:
		return "Diagnostic Buffer"
	default:
		return "Unknown SZL"
	}
}

// getBlockTypeName returns the human-readable name for a block type.
func getBlockTypeName(blockType int) string {
	switch blockType {
	case S7BlockTypeOB:
		return "OB (Organization Block)"
	case S7BlockTypeDB:
		return "DB (Data Block)"
	case S7BlockTypeSDB:
		return "SDB (System Data Block)"
	case S7BlockTypeFC:
		return "FC (Function)"
	case S7BlockTypeSFC:
		return "SFC (System Function)"
	case S7BlockTypeFB:
		return "FB (Function Block)"
	case S7BlockTypeSFB:
		return "SFB (System Function Block)"
	default:
		return "Unknown Block Type"
	}
}

// getAlarmTypeName returns the human-readable name for an alarm type.
func getAlarmTypeName(alarmType int) string {
	switch alarmType {
	case S7AlarmTypeScan:
		return "Scan Alarm"
	case S7AlarmTypeAlarm8:
		return "Alarm_8"
	case S7AlarmTypeAlarm8P:
		return "Alarm_8P"
	case S7AlarmTypeNotify:
		return "Notify"
	case S7AlarmTypeAlarmS:
		return "Alarm_S"
	case S7AlarmTypeAlarmSQ:
		return "Alarm_SQ"
	case S7AlarmTypeAlarm:
		return "Alarm"
	case S7AlarmTypeAlarmAck:
		return "Alarm Acknowledge"
	case S7AlarmTypeAlarmLock:
		return "Alarm Lock/Unlock"
	default:
		return "Unknown Alarm"
	}
}

// getCPUSubfunctionName returns the name for a CPU function subfunction.
func getCPUSubfunctionName(subFunc int) string {
	switch subFunc {
	case S7UserDataCPUReadSZL:
		return "Read SZL"
	case S7UserDataCPUMsgService:
		return "Message Service"
	case S7UserDataCPUDiagMessage:
		return "Diagnostic Message"
	case S7UserDataCPUAlarmQuery:
		return "Alarm Query"
	default:
		return "Unknown"
	}
}

// getTimeSubfunctionName returns the name for a Time function subfunction.
func getTimeSubfunctionName(subFunc int) string {
	switch subFunc {
	case S7UserDataTimeRead:
		return "Read Clock"
	case S7UserDataTimeSet:
		return "Set Clock"
	case S7UserDataTimeReadF:
		return "Read Clock (F)"
	case S7UserDataTimeSet2:
		return "Set Clock (2)"
	default:
		return "Unknown"
	}
}

// getCyclicSubfunctionName returns the name for a Cyclic data subfunction.
func getCyclicSubfunctionName(subFunc int) string {
	switch subFunc {
	case S7UserDataCyclicMem:
		return "Memory"
	case S7UserDataCyclicUnsubscr:
		return "Unsubscribe"
	default:
		return "Unknown"
	}
}

