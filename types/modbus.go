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

package types

import (
	"encoding/hex"
	"encoding/json"
	"hash/crc32"
	"strconv"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/encoder"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	fieldProtocolID   = "ProtocolID"
	fieldUnitID       = "UnitID"
	fieldPayload      = "Payload"
	fieldException    = "Exception"
	fieldFunctionCode = "FunctionCode"
)

var fieldsModbus = []string{
	fieldTimestamp,
	fieldTransactionID, // int32
	fieldProtocolID,    // int32
	fieldLength,        // int32
	fieldUnitID,        // int32
	fieldPayload,       // []byte
	fieldException,     // bool
	fieldFunctionCode,  // int32
	fieldSrcIP,
	fieldDstIP,
	fieldSrcPort,
	fieldDstPort,
	fieldCommunityID,
	"Transport", "MessageRole", "ParseStatus", "ParseError", "Bank",
	"HasAddress", "Address", "Quantity", "Values",
	"HasReadAddress", "ReadAddress", "ReadQuantity",
	"HasWriteAddress", "WriteAddress", "WriteQuantity", "WriteValues",
	"ExceptionCode", "HasDiagnostic", "DiagnosticSubfunction", "DiagnosticData",
	"MEIType", "ReadDeviceIDCode", "DeviceIDObjects", "FileRecords",
	"AndMask", "OrMask", "CorrelationStatus", "RequestTimestamp", "ResponseLatency",
	"DeviceIDObjectID", "DeviceIDConformityLevel", "DeviceIDMoreFollows", "DeviceIDNextObjectID",
	"HasMBAP", "HasChecksum", "ChecksumValid", "Broadcast", "LostBytes",
}

// CSVHeader returns the CSV header for the audit record.
func (a *Modbus) CSVHeader() []string {
	return filter(fieldsModbus)
}

// CSVRecord returns the CSV record for the audit record.
func (a *Modbus) CSVRecord() []string {
	return filter(a.csvRecord())
}

// csvRecord returns all values before field selection.
func (a *Modbus) csvRecord() []string {
	return []string{
		formatTimestamp(a.Timestamp),
		formatInt32(a.TransactionID), // int32
		formatInt32(a.ProtocolID),    // int32
		formatInt32(a.Length),        // int32
		formatInt32(a.UnitID),        // int32
		hex.EncodeToString(a.Payload),
		strconv.FormatBool(a.Exception),
		formatInt32(a.FunctionCode),
		a.SrcIP,
		a.DstIP,
		formatInt32(a.SrcPort),
		formatInt32(a.DstPort),
		a.CommunityID,
		a.Transport, a.MessageRole, a.ParseStatus, a.ParseError, a.Bank,
		strconv.FormatBool(a.HasAddress), formatUint32(a.Address), formatUint32(a.Quantity), modbusJSONCell(a.Values),
		strconv.FormatBool(a.HasReadAddress), formatUint32(a.ReadAddress), formatUint32(a.ReadQuantity),
		strconv.FormatBool(a.HasWriteAddress), formatUint32(a.WriteAddress), formatUint32(a.WriteQuantity), modbusJSONCell(a.WriteValues),
		formatUint32(a.ExceptionCode), strconv.FormatBool(a.HasDiagnostic), formatUint32(a.DiagnosticSubfunction), hex.EncodeToString(a.DiagnosticData),
		formatUint32(a.MEIType), formatUint32(a.ReadDeviceIDCode), modbusJSONCell(a.DeviceIDObjects), modbusJSONCell(a.FileRecords),
		formatUint32(a.AndMask), formatUint32(a.OrMask), a.CorrelationStatus, formatTimestamp(a.RequestTimestamp), strconv.FormatInt(a.ResponseLatency, 10),
		formatUint32(a.DeviceIDObjectID), formatUint32(a.DeviceIDConformityLevel), strconv.FormatBool(a.DeviceIDMoreFollows), formatUint32(a.DeviceIDNextObjectID),
		strconv.FormatBool(a.HasMBAP), strconv.FormatBool(a.HasChecksum), strconv.FormatBool(a.ChecksumValid), strconv.FormatBool(a.Broadcast),
		strconv.FormatInt(a.LostBytes, 10),
	}
}

// modbusJSONCell preserves repeated evidence, including base64-encoded nested bytes.
func modbusJSONCell(value any) string {
	data, _ := json.Marshal(value) // Modbus slices contain only protobuf scalar/message fields.
	return string(data)
}

// Time returns the timestamp associated with the audit record.
func (a *Modbus) Time() int64 {
	return a.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (a *Modbus) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	copy := *a
	copy.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(&copy)
}

var modbusTCPMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_Modbus.String()),
		Help: Type_NC_Modbus.String() + " audit records",
	},
	[]string{fieldFunctionCode, fieldException},
)

// Inc increments the metrics for the audit record.
func (a *Modbus) Inc() {
	functionCode := "unknown"
	switch {
	case a.ParseStatus == "lost":
		// Loss markers carry no function code; counting them as 0 would be
		// indistinguishable from a decoded record.
		functionCode = "lost"
	case a.FunctionCode >= 0 && a.FunctionCode <= 255:
		functionCode = formatInt32(a.FunctionCode)
	}
	modbusTCPMetric.WithLabelValues(functionCode, strconv.FormatBool(a.Exception)).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (a *Modbus) SetPacketContext(ctx *PacketContext) {
	a.SrcIP = ctx.SrcIP
	a.DstIP = ctx.DstIP
	a.SrcPort = ctx.SrcPort
	a.DstPort = ctx.DstPort
	a.CommunityID = ctx.CommunityID
}

// Src returns the source address of the audit record.
func (a *Modbus) Src() string {
	return a.SrcIP
}

// Dst returns the destination address of the audit record.
func (a *Modbus) Dst() string {
	return a.DstIP
}

var modbusEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (a *Modbus) Encode() []string {
	fields := filter(fieldsModbus)
	values := make([]string, len(fields))
	// Select before stateful encoding; duplicate columns reuse one observation.
	encoded := make(map[string]string, len(fields))
	for i, field := range fields {
		if value, ok := encoded[field]; ok {
			values[i] = value
			continue
		}
		var value string
		switch field {
		case fieldTimestamp:
			value = modbusEncoder.Int64(field, a.Timestamp)
		case fieldTransactionID:
			value = modbusEncoder.Int32(field, a.TransactionID)
		case fieldProtocolID:
			value = modbusEncoder.Int32(field, a.ProtocolID)
		case fieldLength:
			value = modbusEncoder.Int32(field, a.Length)
		case fieldUnitID:
			value = modbusEncoder.Int32(field, a.UnitID)
		case fieldPayload, fieldCommunityID:
			// Low 16 bits of IEEE CRC32 are deterministic buckets, not ordinal IDs.
			// Collisions are intentional; numeric normalization retains no dictionary.
			// This is lossy feature encoding, not cryptographic anonymization.
			data := a.Payload
			if field == fieldCommunityID {
				data = []byte(a.CommunityID)
			}
			value = modbusEncoder.Uint32(field, crc32.ChecksumIEEE(data)&0xffff)
		case fieldException:
			value = modbusEncoder.Bool(a.Exception)
		case fieldFunctionCode:
			value = modbusEncoder.Int32(field, a.FunctionCode)
		case fieldSrcIP:
			value = modbusEncoder.String(field, a.SrcIP)
		case fieldDstIP:
			value = modbusEncoder.String(field, a.DstIP)
		case fieldSrcPort:
			value = modbusEncoder.Int32(field, a.SrcPort)
		case fieldDstPort:
			value = modbusEncoder.Int32(field, a.DstPort)
		case "HasAddress":
			value = modbusEncoder.Bool(a.HasAddress)
		case "HasMBAP":
			value = modbusEncoder.Bool(a.HasMBAP)
		case "HasChecksum":
			value = modbusEncoder.Bool(a.HasChecksum)
		case "ChecksumValid":
			value = modbusEncoder.Bool(a.ChecksumValid)
		case "Broadcast":
			value = modbusEncoder.Bool(a.Broadcast)
		case "HasReadAddress":
			value = modbusEncoder.Bool(a.HasReadAddress)
		case "HasWriteAddress":
			value = modbusEncoder.Bool(a.HasWriteAddress)
		case "HasDiagnostic":
			value = modbusEncoder.Bool(a.HasDiagnostic)
		case "DeviceIDMoreFollows":
			value = modbusEncoder.Bool(a.DeviceIDMoreFollows)
		case "Address":
			value = modbusEncoder.Uint32(field, a.Address)
		case "Quantity":
			value = modbusEncoder.Uint32(field, a.Quantity)
		case "ReadAddress":
			value = modbusEncoder.Uint32(field, a.ReadAddress)
		case "ReadQuantity":
			value = modbusEncoder.Uint32(field, a.ReadQuantity)
		case "WriteAddress":
			value = modbusEncoder.Uint32(field, a.WriteAddress)
		case "WriteQuantity":
			value = modbusEncoder.Uint32(field, a.WriteQuantity)
		case "ExceptionCode":
			value = modbusEncoder.Uint32(field, a.ExceptionCode)
		case "DiagnosticSubfunction":
			value = modbusEncoder.Uint32(field, a.DiagnosticSubfunction)
		case "MEIType":
			value = modbusEncoder.Uint32(field, a.MEIType)
		case "ReadDeviceIDCode":
			value = modbusEncoder.Uint32(field, a.ReadDeviceIDCode)
		case "AndMask":
			value = modbusEncoder.Uint32(field, a.AndMask)
		case "OrMask":
			value = modbusEncoder.Uint32(field, a.OrMask)
		case "RequestTimestamp":
			value = modbusEncoder.Int64(field, a.RequestTimestamp)
		case "ResponseLatency":
			value = modbusEncoder.Int64(field, a.ResponseLatency)
		case "LostBytes":
			value = modbusEncoder.Int64(field, a.LostBytes)
		case "DeviceIDObjectID":
			value = modbusEncoder.Uint32(field, a.DeviceIDObjectID)
		case "DeviceIDConformityLevel":
			value = modbusEncoder.Uint32(field, a.DeviceIDConformityLevel)
		case "DeviceIDNextObjectID":
			value = modbusEncoder.Uint32(field, a.DeviceIDNextObjectID)
		case "Transport", "MessageRole", "ParseStatus", "ParseError", "Bank", "CorrelationStatus",
			"Values", "WriteValues", "DiagnosticData", "DeviceIDObjects", "FileRecords":
			var data string
			switch field {
			case "Transport":
				data = a.Transport
			case "MessageRole":
				data = a.MessageRole
			case "ParseStatus":
				data = a.ParseStatus
			case "ParseError":
				data = a.ParseError
			case "Bank":
				data = a.Bank
			case "CorrelationStatus":
				data = a.CorrelationStatus
			case "Values":
				data = modbusJSONCell(a.Values)
			case "WriteValues":
				data = modbusJSONCell(a.WriteValues)
			case "DiagnosticData":
				data = string(a.DiagnosticData)
			case "DeviceIDObjects":
				data = modbusJSONCell(a.DeviceIDObjects)
			case "FileRecords":
				data = modbusJSONCell(a.FileRecords)
			}
			value = modbusEncoder.Uint32(field, crc32.ChecksumIEEE([]byte(data))&0xffff)
		}
		values[i], encoded[field] = value, value
	}
	return values
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (a *Modbus) Analyze() {}

// NetcapType returns the type of the current audit record
func (a *Modbus) NetcapType() Type {
	return Type_NC_Modbus
}
