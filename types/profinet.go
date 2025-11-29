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
	fieldPROFINETFrameID            = "FrameID"
	fieldPROFINETFrameType          = "FrameType"
	fieldPROFINETFrameTypeName      = "FrameTypeName"
	fieldPROFINETBlockType          = "BlockType"
	fieldPROFINETBlockTypeName      = "BlockTypeName"
	fieldPROFINETBlockLength        = "BlockLength"
	fieldPROFINETBlockVersionHigh   = "BlockVersionHigh"
	fieldPROFINETBlockVersionLow    = "BlockVersionLow"
	fieldPROFINETServiceID          = "ServiceID"
	fieldPROFINETServiceName        = "ServiceName"
	fieldPROFINETOperationType      = "OperationType"
	fieldPROFINETOperationTypeName  = "OperationTypeName"
	fieldPROFINETIsRequest          = "IsRequest"
	fieldPROFINETARUUID             = "ARUUID"
	fieldPROFINETAPI                = "API"
	fieldPROFINETSlotNumber         = "SlotNumber"
	fieldPROFINETSubslotNumber      = "SubslotNumber"
	fieldPROFINETIODataLength       = "IODataLength"
	fieldPROFINETIOCS               = "IOCS"
	fieldPROFINETIOPS               = "IOPS"
	fieldPROFINETIOStatusName       = "IOStatusName"
	fieldPROFINETAlarmType          = "AlarmType"
	fieldPROFINETAlarmTypeName      = "AlarmTypeName"
	fieldPROFINETAlarmPriority      = "AlarmPriority"
	fieldPROFINETDiagnosisType      = "DiagnosisType"
	fieldPROFINETDiagnosisTypeName  = "DiagnosisTypeName"
	fieldPROFINETChannelNumber      = "ChannelNumber"
	fieldPROFINETErrorType          = "ErrorType"
	fieldPROFINETErrorTypeName      = "ErrorTypeName"
	fieldPROFINETStationName        = "StationName"
	fieldPROFINETVendorID           = "VendorID"
	fieldPROFINETDeviceID           = "DeviceID"
	fieldPROFINETDeviceRole         = "DeviceRole"
	fieldPROFINETSequenceNumber     = "SequenceNumber"
	fieldPROFINETCycleCounter       = "CycleCounter"
	fieldPROFINETDataStatus         = "DataStatus"
	fieldPROFINETTransferStatus     = "TransferStatus"
	fieldPROFINETIsSecurityRelevant = "IsSecurityRelevant"
	fieldPROFINETIsCriticalOperation = "IsCriticalOperation"
	fieldPROFINETIsAlarm            = "IsAlarm"
	fieldPROFINETIsDiagnostic       = "IsDiagnostic"
)

var fieldsPROFINET = []string{
	fieldTimestamp,
	fieldSrcIP,
	fieldDstIP,
	fieldSrcPort,
	fieldDstPort,
	fieldPROFINETFrameID,
	fieldPROFINETFrameType,
	fieldPROFINETFrameTypeName,
	fieldPROFINETBlockType,
	fieldPROFINETBlockTypeName,
	fieldPROFINETBlockLength,
	fieldPROFINETBlockVersionHigh,
	fieldPROFINETBlockVersionLow,
	fieldPROFINETServiceID,
	fieldPROFINETServiceName,
	fieldPROFINETOperationType,
	fieldPROFINETOperationTypeName,
	fieldPROFINETIsRequest,
	fieldPROFINETARUUID,
	fieldPROFINETAPI,
	fieldPROFINETSlotNumber,
	fieldPROFINETSubslotNumber,
	fieldPROFINETIODataLength,
	fieldPROFINETIOCS,
	fieldPROFINETIOPS,
	fieldPROFINETIOStatusName,
	fieldPROFINETAlarmType,
	fieldPROFINETAlarmTypeName,
	fieldPROFINETAlarmPriority,
	fieldPROFINETDiagnosisType,
	fieldPROFINETDiagnosisTypeName,
	fieldPROFINETChannelNumber,
	fieldPROFINETErrorType,
	fieldPROFINETErrorTypeName,
	fieldPROFINETStationName,
	fieldPROFINETVendorID,
	fieldPROFINETDeviceID,
	fieldPROFINETDeviceRole,
	fieldPROFINETSequenceNumber,
	fieldPROFINETCycleCounter,
	fieldPROFINETDataStatus,
	fieldPROFINETTransferStatus,
	fieldPROFINETIsSecurityRelevant,
	fieldPROFINETIsCriticalOperation,
	fieldPROFINETIsAlarm,
	fieldPROFINETIsDiagnostic,
}

// CSVHeader returns the CSV header for the audit record.
func (p *PROFINET) CSVHeader() []string {
	return filter(fieldsPROFINET)
}

// CSVRecord returns the CSV record for the audit record.
func (p *PROFINET) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(p.Timestamp),
		p.SrcIP,
		p.DstIP,
		formatInt32(p.SrcPort),
		formatInt32(p.DstPort),
		formatInt32(p.FrameID),
		p.FrameType,
		p.FrameTypeName,
		formatInt32(p.BlockType),
		p.BlockTypeName,
		formatInt32(p.BlockLength),
		formatInt32(p.BlockVersionHigh),
		formatInt32(p.BlockVersionLow),
		formatInt32(p.ServiceID),
		p.ServiceName,
		formatInt32(p.OperationType),
		p.OperationTypeName,
		strconv.FormatBool(p.IsRequest),
		formatUint32(p.ARUUID),
		formatUint32(p.API),
		formatInt32(p.SlotNumber),
		formatInt32(p.SubslotNumber),
		formatInt32(p.IODataLength),
		formatInt32(p.IOCS),
		formatInt32(p.IOPS),
		p.IOStatusName,
		formatInt32(p.AlarmType),
		p.AlarmTypeName,
		formatInt32(p.AlarmPriority),
		formatInt32(p.DiagnosisType),
		p.DiagnosisTypeName,
		formatInt32(p.ChannelNumber),
		formatInt32(p.ErrorType),
		p.ErrorTypeName,
		p.StationName,
		p.VendorID,
		p.DeviceID,
		p.DeviceRole,
		formatUint32(p.SequenceNumber),
		formatInt32(p.CycleCounter),
		formatInt32(p.DataStatus),
		formatInt32(p.TransferStatus),
		strconv.FormatBool(p.IsSecurityRelevant),
		strconv.FormatBool(p.IsCriticalOperation),
		strconv.FormatBool(p.IsAlarm),
		strconv.FormatBool(p.IsDiagnostic),
	})
}

// Time returns the timestamp associated with the audit record.
func (p *PROFINET) Time() int64 {
	return p.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (p *PROFINET) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	p.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(p)
}

var profinetMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_PROFINET.String()),
		Help: Type_NC_PROFINET.String() + " audit records",
	},
	fieldsPROFINET[1:],
)

// Inc increments the metrics for the audit record.
func (p *PROFINET) Inc() {
	profinetMetric.WithLabelValues(p.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (p *PROFINET) SetPacketContext(ctx *PacketContext) {
	p.SrcIP = ctx.SrcIP
	p.DstIP = ctx.DstIP
	p.SrcPort = ctx.SrcPort
	p.DstPort = ctx.DstPort
}

// Src returns the source address of the audit record.
func (p *PROFINET) Src() string {
	return p.SrcIP
}

// Dst returns the destination address of the audit record.
func (p *PROFINET) Dst() string {
	return p.DstIP
}

var profinetEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration.
func (p *PROFINET) Encode() []string {
	return filter([]string{
		profinetEncoder.Int64(fieldTimestamp, p.Timestamp),
		profinetEncoder.String(fieldSrcIP, p.SrcIP),
		profinetEncoder.String(fieldDstIP, p.DstIP),
		profinetEncoder.Int32(fieldSrcPort, p.SrcPort),
		profinetEncoder.Int32(fieldDstPort, p.DstPort),
		profinetEncoder.Int32(fieldPROFINETFrameID, p.FrameID),
		profinetEncoder.String(fieldPROFINETFrameType, p.FrameType),
		profinetEncoder.String(fieldPROFINETFrameTypeName, p.FrameTypeName),
		profinetEncoder.Int32(fieldPROFINETBlockType, p.BlockType),
		profinetEncoder.String(fieldPROFINETBlockTypeName, p.BlockTypeName),
		profinetEncoder.Int32(fieldPROFINETBlockLength, p.BlockLength),
		profinetEncoder.Int32(fieldPROFINETBlockVersionHigh, p.BlockVersionHigh),
		profinetEncoder.Int32(fieldPROFINETBlockVersionLow, p.BlockVersionLow),
		profinetEncoder.Int32(fieldPROFINETServiceID, p.ServiceID),
		profinetEncoder.String(fieldPROFINETServiceName, p.ServiceName),
		profinetEncoder.Int32(fieldPROFINETOperationType, p.OperationType),
		profinetEncoder.String(fieldPROFINETOperationTypeName, p.OperationTypeName),
		profinetEncoder.Bool(p.IsRequest),
		profinetEncoder.Uint32(fieldPROFINETARUUID, p.ARUUID),
		profinetEncoder.Uint32(fieldPROFINETAPI, p.API),
		profinetEncoder.Int32(fieldPROFINETSlotNumber, p.SlotNumber),
		profinetEncoder.Int32(fieldPROFINETSubslotNumber, p.SubslotNumber),
		profinetEncoder.Int32(fieldPROFINETIODataLength, p.IODataLength),
		profinetEncoder.Int32(fieldPROFINETIOCS, p.IOCS),
		profinetEncoder.Int32(fieldPROFINETIOPS, p.IOPS),
		profinetEncoder.String(fieldPROFINETIOStatusName, p.IOStatusName),
		profinetEncoder.Int32(fieldPROFINETAlarmType, p.AlarmType),
		profinetEncoder.String(fieldPROFINETAlarmTypeName, p.AlarmTypeName),
		profinetEncoder.Int32(fieldPROFINETAlarmPriority, p.AlarmPriority),
		profinetEncoder.Int32(fieldPROFINETDiagnosisType, p.DiagnosisType),
		profinetEncoder.String(fieldPROFINETDiagnosisTypeName, p.DiagnosisTypeName),
		profinetEncoder.Int32(fieldPROFINETChannelNumber, p.ChannelNumber),
		profinetEncoder.Int32(fieldPROFINETErrorType, p.ErrorType),
		profinetEncoder.String(fieldPROFINETErrorTypeName, p.ErrorTypeName),
		profinetEncoder.String(fieldPROFINETStationName, p.StationName),
		profinetEncoder.String(fieldPROFINETVendorID, p.VendorID),
		profinetEncoder.String(fieldPROFINETDeviceID, p.DeviceID),
		profinetEncoder.String(fieldPROFINETDeviceRole, p.DeviceRole),
		profinetEncoder.Uint32(fieldPROFINETSequenceNumber, p.SequenceNumber),
		profinetEncoder.Int32(fieldPROFINETCycleCounter, p.CycleCounter),
		profinetEncoder.Int32(fieldPROFINETDataStatus, p.DataStatus),
		profinetEncoder.Int32(fieldPROFINETTransferStatus, p.TransferStatus),
		profinetEncoder.Bool(p.IsSecurityRelevant),
		profinetEncoder.Bool(p.IsCriticalOperation),
		profinetEncoder.Bool(p.IsAlarm),
		profinetEncoder.Bool(p.IsDiagnostic),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (p *PROFINET) Analyze() {}

// NetcapType returns the type of the current audit record.
func (p *PROFINET) NetcapType() Type {
	return Type_NC_PROFINET
}

