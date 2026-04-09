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
	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/decoder"
	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/core"
	logging "github.com/dreadl0ck/netcap/internal/logger"
	"github.com/dreadl0ck/netcap/types"
)

var modbusLog = zap.NewNop()

const serviceModbus = "Modbus"

// MBAP Header constants
const (
	// MBAP (Modbus Application Protocol) header size is 7 bytes:
	// - Transaction ID: 2 bytes
	// - Protocol ID: 2 bytes (always 0x0000 for Modbus)
	// - Length: 2 bytes
	// - Unit ID: 1 byte
	mbapHeaderSize = 7

	// Modbus TCP Protocol ID is always 0x0000
	modbusProtocolID = 0x0000

	// Minimum PDU size: Function Code (1 byte)
	minPDUSize = 1

	// Maximum PDU size per Modbus specification
	maxPDUSize = 253
)

// Decoder for protocol analysis and writing audit records to disk.
var Decoder = &decoder.StreamDecoder{
	Type:        types.Type_NC_Modbus,
	Name:        serviceModbus,
	Description: "Modbus is a serial communications protocol for ICS/SCADA PLCs and industrial devices",
	PostInit: func(d *decoder.StreamDecoder) error {
		var err error
		modbusLog, _, err = logging.InitZapLogger(
			decoderconfig.Instance.Out,
			"modbus",
			decoderconfig.Instance.Debug,
		)
		return err
	},
	CanDecode: func(client, server []byte) bool {
		// Check both directions for Modbus TCP traffic
		return canDecodeModbus(client) || canDecodeModbus(server)
	},
	DeInit: func(sd *decoder.StreamDecoder) error {
		return modbusLog.Sync()
	},
	Factory: &modbusReader{},
	Typ:     core.TCP, // Modbus TCP uses TCP port 502
}

// canDecodeModbus checks if the data looks like a Modbus TCP message.
// Modbus TCP has a very specific MBAP header format that makes detection reliable.
func canDecodeModbus(data []byte) bool {
	if len(data) < mbapHeaderSize+minPDUSize {
		return false
	}

	// Protocol Identifier (bytes 2-3) must be 0x0000 for Modbus
	// This is the most reliable signature for Modbus TCP
	protocolID := uint16(data[2])<<8 | uint16(data[3])
	if protocolID != modbusProtocolID {
		return false
	}

	// Length field (bytes 4-5) - big endian
	// Length = Unit ID (1 byte) + PDU length
	length := uint16(data[4])<<8 | uint16(data[5])

	// Sanity checks on length
	// Length must be at least 2 (Unit ID + 1 byte function code)
	// Length must not exceed 254 (Unit ID + max PDU of 253)
	if length < 2 || length > 254 {
		return false
	}

	// Function code validation (first byte of PDU after MBAP header)
	funcCode := data[7] & 0x7F // Mask out exception bit
	if !isValidFunctionCode(funcCode) {
		return false
	}

	return true
}

// isValidFunctionCode checks if the function code is a known Modbus function.
func isValidFunctionCode(code uint8) bool {
	switch code {
	case FuncReadCoils,
		FuncReadDiscreteInputs,
		FuncReadHoldingRegisters,
		FuncReadInputRegisters,
		FuncWriteSingleCoil,
		FuncWriteSingleRegister,
		FuncReadExceptionStatus,
		FuncDiagnostic,
		FuncGetCommEventCounter,
		FuncGetCommEventLog,
		FuncWriteMultipleCoils,
		FuncWriteMultipleRegisters,
		FuncReportSlaveID,
		FuncReadFileRecord,
		FuncWriteFileRecord,
		FuncMaskWriteRegister,
		FuncReadWriteMultipleRegisters,
		FuncReadFIFOQueue,
		FuncEncapsulatedInterface: // Also covers FuncReadDeviceIdentification (same code 0x2B)
		return true
	}
	return false
}

