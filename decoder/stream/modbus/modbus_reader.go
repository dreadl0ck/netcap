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

package modbus

import (
	"bytes"
	"sync/atomic"

	"go.uber.org/zap"

	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/core"
	"github.com/dreadl0ck/netcap/types"
)

// Modbus Function Codes (standard functions per Modbus Application Protocol Specification V1.1b3)
const (
	// Bit access - Single bits
	FuncReadCoils          = 0x01 // Read Coils (outputs)
	FuncReadDiscreteInputs = 0x02 // Read Discrete Inputs

	// Bit access - Multiple bits
	FuncWriteSingleCoil    = 0x05 // Write Single Coil
	FuncWriteMultipleCoils = 0x0F // Write Multiple Coils

	// 16-bit access - Single registers
	FuncReadHoldingRegisters = 0x03 // Read Holding Registers
	FuncReadInputRegisters   = 0x04 // Read Input Registers
	FuncWriteSingleRegister  = 0x06 // Write Single Register

	// 16-bit access - Multiple registers
	FuncWriteMultipleRegisters     = 0x10 // Write Multiple Registers
	FuncReadWriteMultipleRegisters = 0x17 // Read/Write Multiple Registers
	FuncMaskWriteRegister          = 0x16 // Mask Write Register
	FuncReadFIFOQueue              = 0x18 // Read FIFO Queue

	// File record access
	FuncReadFileRecord  = 0x14 // Read File Record
	FuncWriteFileRecord = 0x15 // Write File Record

	// Diagnostics
	FuncReadExceptionStatus  = 0x07 // Read Exception Status
	FuncDiagnostic           = 0x08 // Diagnostic
	FuncGetCommEventCounter  = 0x0B // Get Comm Event Counter
	FuncGetCommEventLog      = 0x0C // Get Comm Event Log
	FuncReportSlaveID        = 0x11 // Report Slave ID
	FuncEncapsulatedInterface = 0x2B // Encapsulated Interface Transport (includes Read Device Identification)

	// User-defined function codes (65-72, 100-110)
	// Vendor-specific, not parsed here
)

// Diagnostic sub-function codes
const (
	DiagReturnQueryData                = 0x00
	DiagRestartCommunications          = 0x01
	DiagReturnDiagnosticRegister       = 0x02
	DiagChangeASCIIInputDelimiter      = 0x03
	DiagForceListenOnlyMode            = 0x04
	DiagClearCountersAndDiagnosticReg  = 0x0A
	DiagReturnBusMessageCount          = 0x0B
	DiagReturnBusCommunicationError    = 0x0C
	DiagReturnBusExceptionErrorCount   = 0x0D
	DiagReturnSlaveMessageCount        = 0x0E
	DiagReturnSlaveNoResponseCount     = 0x0F
	DiagReturnSlaveNAKCount            = 0x10
	DiagReturnSlaveBusyCount           = 0x11
	DiagReturnBusCharacterOverrunCount = 0x12
	DiagClearOverrunCounter            = 0x14
)

// Exception codes
const (
	ExceptionIllegalFunction         = 0x01
	ExceptionIllegalDataAddress      = 0x02
	ExceptionIllegalDataValue        = 0x03
	ExceptionSlaveDeviceFailure      = 0x04
	ExceptionAcknowledge             = 0x05
	ExceptionSlaveDeviceBusy         = 0x06
	ExceptionNegativeAcknowledge     = 0x07
	ExceptionMemoryParityError       = 0x08
	ExceptionGatewayPathUnavailable  = 0x0A
	ExceptionGatewayTargetNoResponse = 0x0B
)

// Critical function codes that write to PLCs
var criticalFunctions = map[uint8]bool{
	FuncWriteSingleCoil:            true,
	FuncWriteSingleRegister:        true,
	FuncWriteMultipleCoils:         true,
	FuncWriteMultipleRegisters:     true,
	FuncReadWriteMultipleRegisters: true,
	FuncMaskWriteRegister:          true,
	FuncWriteFileRecord:            true,
}

// Diagnostic/maintenance functions
var diagnosticFunctions = map[uint8]bool{
	FuncReadExceptionStatus: true,
	FuncDiagnostic:          true,
	FuncGetCommEventCounter: true,
	FuncGetCommEventLog:     true,
	FuncReportSlaveID:       true,
}

type modbusReader struct {
	conversation *core.ConversationInfo
}

// New returns a new Modbus reader.
func (m *modbusReader) New(conversation *core.ConversationInfo) core.StreamDecoderInterface {
	return &modbusReader{
		conversation: conversation,
	}
}

// Decode parses Modbus TCP messages from the stream.
func (m *modbusReader) Decode() {
	if Decoder.Writer == nil {
		modbusLog.Error("Modbus Decoder.Writer is nil")
		return
	}

	var buf bytes.Buffer

	for _, data := range m.conversation.Data {
		buf.Write(data.Raw())
	}

	frameData := buf.Bytes()
	offset := 0

	for offset < len(frameData)-mbapHeaderSize {
		// Validate MBAP header
		if !m.isModbusHeader(frameData[offset:]) {
			offset++
			continue
		}

		msg, consumed := m.parseModbusMessage(frameData[offset:])
		if msg != nil {
			msg.SrcIP = m.conversation.ClientIP
			msg.DstIP = m.conversation.ServerIP
			msg.SrcPort = int32(m.conversation.ClientPort)
			msg.DstPort = int32(m.conversation.ServerPort)

			err := Decoder.Writer.Write(msg)
			if err != nil {
				modbusLog.Error("failed to write Modbus record", zap.Error(err))
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

// isModbusHeader checks if the data starts with a valid Modbus MBAP header.
func (m *modbusReader) isModbusHeader(data []byte) bool {
	if len(data) < mbapHeaderSize+minPDUSize {
		return false
	}

	// Protocol ID must be 0x0000
	protocolID := uint16(data[2])<<8 | uint16(data[3])
	if protocolID != modbusProtocolID {
		return false
	}

	// Validate length field
	length := uint16(data[4])<<8 | uint16(data[5])
	if length < 2 || length > 254 {
		return false
	}

	return true
}

// parseModbusMessage parses a Modbus TCP message and returns the record and bytes consumed.
func (m *modbusReader) parseModbusMessage(data []byte) (*types.Modbus, int) {
	if len(data) < mbapHeaderSize+minPDUSize {
		return nil, 0
	}

	// Parse MBAP Header (7 bytes)
	transactionID := uint16(data[0])<<8 | uint16(data[1])
	protocolID := uint16(data[2])<<8 | uint16(data[3])
	length := uint16(data[4])<<8 | uint16(data[5])
	unitID := data[6]

	// Validate we have enough data
	totalLength := int(mbapHeaderSize) + int(length) - 1 // -1 because length includes unit ID
	if len(data) < totalLength {
		return nil, 0
	}

	// Parse PDU (starts at byte 7)
	funcCode := data[7]
	isException := (funcCode & 0x80) != 0
	actualFuncCode := funcCode & 0x7F

	msg := &types.Modbus{
		Timestamp:     m.conversation.FirstClientPacket.UnixNano(),
		TransactionID: int32(transactionID),
		ProtocolID:    int32(protocolID),
		Length:        int32(length),
		UnitID:        int32(unitID),
		FunctionCode:  int32(actualFuncCode),
		Exception:     isException,
	}

	// Include payload if configured
	if decoderconfig.Instance.IncludePayloads && totalLength > mbapHeaderSize {
		pduLen := totalLength - mbapHeaderSize
		if pduLen > 0 && len(data) >= mbapHeaderSize+pduLen {
			msg.Payload = make([]byte, pduLen)
			copy(msg.Payload, data[mbapHeaderSize:mbapHeaderSize+pduLen])
		}
	}

	return msg, totalLength
}

// GetFunctionCodeName returns the human-readable name for a Modbus function code.
func GetFunctionCodeName(code uint8) string {
	switch code {
	case FuncReadCoils:
		return "Read Coils"
	case FuncReadDiscreteInputs:
		return "Read Discrete Inputs"
	case FuncReadHoldingRegisters:
		return "Read Holding Registers"
	case FuncReadInputRegisters:
		return "Read Input Registers"
	case FuncWriteSingleCoil:
		return "Write Single Coil"
	case FuncWriteSingleRegister:
		return "Write Single Register"
	case FuncReadExceptionStatus:
		return "Read Exception Status"
	case FuncDiagnostic:
		return "Diagnostic"
	case FuncGetCommEventCounter:
		return "Get Comm Event Counter"
	case FuncGetCommEventLog:
		return "Get Comm Event Log"
	case FuncWriteMultipleCoils:
		return "Write Multiple Coils"
	case FuncWriteMultipleRegisters:
		return "Write Multiple Registers"
	case FuncReportSlaveID:
		return "Report Slave ID"
	case FuncReadFileRecord:
		return "Read File Record"
	case FuncWriteFileRecord:
		return "Write File Record"
	case FuncMaskWriteRegister:
		return "Mask Write Register"
	case FuncReadWriteMultipleRegisters:
		return "Read/Write Multiple Registers"
	case FuncReadFIFOQueue:
		return "Read FIFO Queue"
	case FuncEncapsulatedInterface:
		return "Encapsulated Interface Transport"
	default:
		if code >= 65 && code <= 72 {
			return "User Defined Function"
		}
		if code >= 100 && code <= 110 {
			return "User Defined Function"
		}
		return "Unknown"
	}
}

// GetExceptionCodeName returns the human-readable name for a Modbus exception code.
func GetExceptionCodeName(code uint8) string {
	switch code {
	case ExceptionIllegalFunction:
		return "Illegal Function"
	case ExceptionIllegalDataAddress:
		return "Illegal Data Address"
	case ExceptionIllegalDataValue:
		return "Illegal Data Value"
	case ExceptionSlaveDeviceFailure:
		return "Slave Device Failure"
	case ExceptionAcknowledge:
		return "Acknowledge"
	case ExceptionSlaveDeviceBusy:
		return "Slave Device Busy"
	case ExceptionNegativeAcknowledge:
		return "Negative Acknowledge"
	case ExceptionMemoryParityError:
		return "Memory Parity Error"
	case ExceptionGatewayPathUnavailable:
		return "Gateway Path Unavailable"
	case ExceptionGatewayTargetNoResponse:
		return "Gateway Target Device Failed to Respond"
	default:
		return "Unknown Exception"
	}
}

// IsCriticalFunction returns true if the function code is a write operation.
func IsCriticalFunction(code uint8) bool {
	return criticalFunctions[code]
}

// IsDiagnosticFunction returns true if the function code is a diagnostic operation.
func IsDiagnosticFunction(code uint8) bool {
	return diagnosticFunctions[code]
}

