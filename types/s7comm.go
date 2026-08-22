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
	"strconv"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/encoder"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	fieldS7CommTPKTVersion           = "TPKTVersion"
	fieldS7CommTPKTLength            = "TPKTLength"
	fieldS7CommCOTPLength            = "COTPLength"
	fieldS7CommCOTPPDUType           = "COTPPDUType"
	fieldS7CommCOTPPDUTypeName       = "COTPPDUTypeName"
	fieldS7CommCOTPDestRef           = "COTPDestRef"
	fieldS7CommCOTPSrcRef            = "COTPSrcRef"
	fieldS7CommCOTPClass             = "COTPClass"
	fieldS7CommCOTPTPDUNumber        = "COTPTPDUNumber"
	fieldS7CommCOTPLastDataUnit      = "COTPLastDataUnit"
	fieldS7CommProtocolId            = "ProtocolId"
	fieldS7CommMessageType           = "MessageType"
	fieldS7CommMessageTypeName       = "MessageTypeName"
	fieldS7CommReserved              = "Reserved"
	fieldS7CommPDUReference          = "PDUReference"
	fieldS7CommParameterLength       = "ParameterLength"
	fieldS7CommDataLength            = "DataLength"
	fieldS7CommErrorClass            = "ErrorClass"
	fieldS7CommErrorCode             = "ErrorCode"
	fieldS7CommErrorName             = "ErrorName"
	fieldS7CommFunctionCode          = "FunctionCode"
	fieldS7CommFunctionName          = "FunctionName"
	fieldS7CommSubFunction           = "SubFunction"
	fieldS7CommSubFunctionName       = "SubFunctionName"
	fieldS7CommItemCount             = "ItemCount"
	fieldS7CommMaxAmqCalling         = "MaxAmqCalling"
	fieldS7CommMaxAmqCalled          = "MaxAmqCalled"
	fieldS7CommPDUSize               = "PDUSize"
	fieldS7CommCPUType               = "CPUType"
	fieldS7CommPLCSerialNumber       = "PLCSerialNumber"
	fieldS7CommModuleTypeName        = "ModuleTypeName"
	fieldS7CommPlantIdentification   = "PlantIdentification"
	fieldS7CommUserDataMethodType    = "UserDataMethodType"
	fieldS7CommUserDataFunctionGroup = "UserDataFunctionGroup"
	fieldS7CommUserDataFunctionGroupName = "UserDataFunctionGroupName"
	fieldS7CommUserDataSubFunction   = "UserDataSubFunction"
	fieldS7CommUserDataSequenceNumber = "UserDataSequenceNumber"
	fieldS7CommIsSecurityRelevant    = "IsSecurityRelevant"
	fieldS7CommIsCriticalOperation   = "IsCriticalOperation"
	fieldS7CommPayloadObscured       = "PayloadObscured"
	fieldS7CommS7PlusOpcode          = "S7PlusOpcode"
	fieldS7CommS7PlusOpcodeName      = "S7PlusOpcodeName"
	fieldS7CommS7PlusFunction        = "S7PlusFunction"
)

var fieldsS7Comm = []string{
	fieldTimestamp,
	fieldSrcIP,
	fieldDstIP,
	fieldSrcPort,
	fieldDstPort,
	fieldS7CommTPKTVersion,
	fieldS7CommTPKTLength,
	fieldS7CommCOTPLength,
	fieldS7CommCOTPPDUType,
	fieldS7CommCOTPPDUTypeName,
	fieldS7CommCOTPDestRef,
	fieldS7CommCOTPSrcRef,
	fieldS7CommCOTPClass,
	fieldS7CommCOTPTPDUNumber,
	fieldS7CommCOTPLastDataUnit,
	fieldS7CommProtocolId,
	fieldS7CommMessageType,
	fieldS7CommMessageTypeName,
	fieldS7CommReserved,
	fieldS7CommPDUReference,
	fieldS7CommParameterLength,
	fieldS7CommDataLength,
	fieldS7CommErrorClass,
	fieldS7CommErrorCode,
	fieldS7CommErrorName,
	fieldS7CommFunctionCode,
	fieldS7CommFunctionName,
	fieldS7CommSubFunction,
	fieldS7CommSubFunctionName,
	fieldS7CommItemCount,
	fieldS7CommMaxAmqCalling,
	fieldS7CommMaxAmqCalled,
	fieldS7CommPDUSize,
	fieldS7CommCPUType,
	fieldS7CommPLCSerialNumber,
	fieldS7CommModuleTypeName,
	fieldS7CommPlantIdentification,
	fieldS7CommUserDataMethodType,
	fieldS7CommUserDataFunctionGroup,
	fieldS7CommUserDataFunctionGroupName,
	fieldS7CommUserDataSubFunction,
	fieldS7CommUserDataSequenceNumber,
	fieldS7CommIsSecurityRelevant,
	fieldS7CommIsCriticalOperation,
	fieldS7CommPayloadObscured,
	fieldS7CommS7PlusOpcode,
	fieldS7CommS7PlusOpcodeName,
	fieldS7CommS7PlusFunction,
}

// CSVHeader returns the CSV header for the audit record.
func (s *S7Comm) CSVHeader() []string {
	return filter(fieldsS7Comm)
}

// CSVRecord returns the CSV record for the audit record.
func (s *S7Comm) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(s.Timestamp),
		s.SrcIP,
		s.DstIP,
		formatInt32(s.SrcPort),
		formatInt32(s.DstPort),
		formatInt32(s.TPKTVersion),
		formatInt32(s.TPKTLength),
		formatInt32(s.COTPLength),
		formatInt32(s.COTPPDUType),
		s.COTPPDUTypeName,
		formatInt32(s.COTPDestRef),
		formatInt32(s.COTPSrcRef),
		formatInt32(s.COTPClass),
		formatInt32(s.COTPTPDUNumber),
		strconv.FormatBool(s.COTPLastDataUnit),
		formatInt32(s.ProtocolId),
		formatInt32(s.MessageType),
		s.MessageTypeName,
		formatInt32(s.Reserved),
		formatInt32(s.PDUReference),
		formatInt32(s.ParameterLength),
		formatInt32(s.DataLength),
		formatInt32(s.ErrorClass),
		formatInt32(s.ErrorCode),
		s.ErrorName,
		formatInt32(s.FunctionCode),
		s.FunctionName,
		formatInt32(s.SubFunction),
		s.SubFunctionName,
		formatInt32(s.ItemCount),
		formatInt32(s.MaxAmqCalling),
		formatInt32(s.MaxAmqCalled),
		formatInt32(s.PDUSize),
		s.CPUType,
		s.PLCSerialNumber,
		s.ModuleTypeName,
		s.PlantIdentification,
		formatInt32(s.UserDataMethodType),
		formatInt32(s.UserDataFunctionGroup),
		s.UserDataFunctionGroupName,
		formatInt32(s.UserDataSubFunction),
		formatInt32(s.UserDataSequenceNumber),
		strconv.FormatBool(s.IsSecurityRelevant),
		strconv.FormatBool(s.IsCriticalOperation),
		strconv.FormatBool(s.PayloadObscured),
		formatInt32(s.S7PlusOpcode),
		s.S7PlusOpcodeName,
		formatInt32(s.S7PlusFunction),
	})
}

// Time returns the timestamp associated with the audit record.
func (s *S7Comm) Time() int64 {
	return s.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (s *S7Comm) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	s.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(s)
}

var s7commMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_S7Comm.String()),
		Help: Type_NC_S7Comm.String() + " audit records",
	},
	fieldsS7Comm[1:],
)

// Inc increments the metrics for the audit record.
func (s *S7Comm) Inc() {
	s7commMetric.WithLabelValues(s.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (s *S7Comm) SetPacketContext(ctx *PacketContext) {
	s.SrcIP = ctx.SrcIP
	s.DstIP = ctx.DstIP
	s.SrcPort = ctx.SrcPort
	s.DstPort = ctx.DstPort
}

// Src returns the source address of the audit record.
func (s *S7Comm) Src() string {
	return s.SrcIP
}

// Dst returns the destination address of the audit record.
func (s *S7Comm) Dst() string {
	return s.DstIP
}

var s7commEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration.
func (s *S7Comm) Encode() []string {
	return filter([]string{
		s7commEncoder.Int64(fieldTimestamp, s.Timestamp),
		s7commEncoder.String(fieldSrcIP, s.SrcIP),
		s7commEncoder.String(fieldDstIP, s.DstIP),
		s7commEncoder.Int32(fieldSrcPort, s.SrcPort),
		s7commEncoder.Int32(fieldDstPort, s.DstPort),
		s7commEncoder.Int32(fieldS7CommTPKTVersion, s.TPKTVersion),
		s7commEncoder.Int32(fieldS7CommTPKTLength, s.TPKTLength),
		s7commEncoder.Int32(fieldS7CommCOTPLength, s.COTPLength),
		s7commEncoder.Int32(fieldS7CommCOTPPDUType, s.COTPPDUType),
		s7commEncoder.String(fieldS7CommCOTPPDUTypeName, s.COTPPDUTypeName),
		s7commEncoder.Int32(fieldS7CommCOTPDestRef, s.COTPDestRef),
		s7commEncoder.Int32(fieldS7CommCOTPSrcRef, s.COTPSrcRef),
		s7commEncoder.Int32(fieldS7CommCOTPClass, s.COTPClass),
		s7commEncoder.Int32(fieldS7CommCOTPTPDUNumber, s.COTPTPDUNumber),
		s7commEncoder.Bool(s.COTPLastDataUnit),
		s7commEncoder.Int32(fieldS7CommProtocolId, s.ProtocolId),
		s7commEncoder.Int32(fieldS7CommMessageType, s.MessageType),
		s7commEncoder.String(fieldS7CommMessageTypeName, s.MessageTypeName),
		s7commEncoder.Int32(fieldS7CommReserved, s.Reserved),
		s7commEncoder.Int32(fieldS7CommPDUReference, s.PDUReference),
		s7commEncoder.Int32(fieldS7CommParameterLength, s.ParameterLength),
		s7commEncoder.Int32(fieldS7CommDataLength, s.DataLength),
		s7commEncoder.Int32(fieldS7CommErrorClass, s.ErrorClass),
		s7commEncoder.Int32(fieldS7CommErrorCode, s.ErrorCode),
		s7commEncoder.String(fieldS7CommErrorName, s.ErrorName),
		s7commEncoder.Int32(fieldS7CommFunctionCode, s.FunctionCode),
		s7commEncoder.String(fieldS7CommFunctionName, s.FunctionName),
		s7commEncoder.Int32(fieldS7CommSubFunction, s.SubFunction),
		s7commEncoder.String(fieldS7CommSubFunctionName, s.SubFunctionName),
		s7commEncoder.Int32(fieldS7CommItemCount, s.ItemCount),
		s7commEncoder.Int32(fieldS7CommMaxAmqCalling, s.MaxAmqCalling),
		s7commEncoder.Int32(fieldS7CommMaxAmqCalled, s.MaxAmqCalled),
		s7commEncoder.Int32(fieldS7CommPDUSize, s.PDUSize),
		s7commEncoder.String(fieldS7CommCPUType, s.CPUType),
		s7commEncoder.String(fieldS7CommPLCSerialNumber, s.PLCSerialNumber),
		s7commEncoder.String(fieldS7CommModuleTypeName, s.ModuleTypeName),
		s7commEncoder.String(fieldS7CommPlantIdentification, s.PlantIdentification),
		s7commEncoder.Int32(fieldS7CommUserDataMethodType, s.UserDataMethodType),
		s7commEncoder.Int32(fieldS7CommUserDataFunctionGroup, s.UserDataFunctionGroup),
		s7commEncoder.String(fieldS7CommUserDataFunctionGroupName, s.UserDataFunctionGroupName),
		s7commEncoder.Int32(fieldS7CommUserDataSubFunction, s.UserDataSubFunction),
		s7commEncoder.Int32(fieldS7CommUserDataSequenceNumber, s.UserDataSequenceNumber),
		s7commEncoder.Bool(s.IsSecurityRelevant),
		s7commEncoder.Bool(s.IsCriticalOperation),
		s7commEncoder.Bool(s.PayloadObscured),
		s7commEncoder.Int32(fieldS7CommS7PlusOpcode, s.S7PlusOpcode),
		s7commEncoder.String(fieldS7CommS7PlusOpcodeName, s.S7PlusOpcodeName),
		s7commEncoder.Int32(fieldS7CommS7PlusFunction, s.S7PlusFunction),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (s *S7Comm) Analyze() {}

// NetcapType returns the type of the current audit record.
func (s *S7Comm) NetcapType() Type {
	return Type_NC_S7Comm
}

