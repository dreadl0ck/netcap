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
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/internal/encoder"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	fieldDNP3ParseStatus       = "ParseStatus"
	fieldDNP3ParseError        = "ParseError"
	fieldDNP3LostBytes         = "LostBytes"
	fieldDNP3Control           = "Control"
	fieldDNP3IsMaster          = "IsMaster"
	fieldDNP3IsRequest         = "IsRequest"
	fieldDNP3DirectionMismatch = "DirectionMismatch"

	fieldDNP3LinkFunctionCode     = "LinkFunctionCode"
	fieldDNP3LinkFunctionCodeName = "LinkFunctionCodeName"
	fieldDNP3LinkFCB              = "LinkFCB"
	fieldDNP3LinkFCV              = "LinkFCV"
	fieldDNP3LinkDFC              = "LinkDFC"

	fieldDNP3Destination   = "Destination"
	fieldDNP3Source        = "Source"
	fieldDNP3IsBroadcast   = "IsBroadcast"
	fieldDNP3IsSelfAddress = "IsSelfAddress"

	fieldDNP3ApplicationSeq  = "ApplicationSeq"
	fieldDNP3ConfirmRequired = "ConfirmRequired"
	fieldDNP3Unsolicited     = "Unsolicited"

	fieldDNP3FunctionCodeName   = "FunctionCodeName"
	fieldDNP3IsCriticalFunction = "IsCriticalFunction"
	fieldDNP3IsConfigChange     = "IsConfigChange"
	fieldDNP3IsAuthentication   = "IsAuthentication"

	fieldDNP3InternalIndications    = "InternalIndications"
	fieldDNP3IINBroadcast           = "IINBroadcast"
	fieldDNP3IINClass1              = "IINClass1"
	fieldDNP3IINClass2              = "IINClass2"
	fieldDNP3IINClass3              = "IINClass3"
	fieldDNP3IINNeedTime            = "IINNeedTime"
	fieldDNP3IINLocalControl        = "IINLocalControl"
	fieldDNP3IINDeviceTrouble       = "IINDeviceTrouble"
	fieldDNP3IINDeviceRestart       = "IINDeviceRestart"
	fieldDNP3IINNoFuncCodeSupport   = "IINNoFuncCodeSupport"
	fieldDNP3IINObjectUnknown       = "IINObjectUnknown"
	fieldDNP3IINParameterError      = "IINParameterError"
	fieldDNP3IINEventBufferOverflow = "IINEventBufferOverflow"
	fieldDNP3IINAlreadyExecuting    = "IINAlreadyExecuting"
	fieldDNP3IINConfigCorrupt       = "IINConfigCorrupt"

	fieldDNP3HeaderCRCValid   = "HeaderCRCValid"
	fieldDNP3BlockCRCValid    = "BlockCRCValid"
	fieldDNP3ObjectsTruncated = "ObjectsTruncated"
	fieldDNP3Objects          = "Objects"

	fieldDNP3CorrelationStatus = "CorrelationStatus"
	fieldDNP3RequestTimestamp  = "RequestTimestamp"
	fieldDNP3ResponseLatency   = "ResponseLatency"
	fieldDNP3SBOStatus         = "SBOStatus"
	fieldDNP3SelectTimestamp   = "SelectTimestamp"
	fieldDNP3OperateLatency    = "OperateLatency"
)

var fieldsDNP3 = []string{
	fieldTimestamp,
	fieldSrcIP,
	fieldDstIP,
	fieldSrcPort,
	fieldDstPort,
	fieldDNP3ParseStatus,
	fieldDNP3ParseError,
	fieldDNP3LostBytes,
	fieldLength,
	fieldDNP3Control,
	fieldDNP3IsMaster,
	fieldDNP3IsRequest,
	fieldDNP3DirectionMismatch,
	fieldDNP3LinkFunctionCode,
	fieldDNP3LinkFunctionCodeName,
	fieldDNP3LinkFCB,
	fieldDNP3LinkFCV,
	fieldDNP3LinkDFC,
	fieldDNP3Destination,
	fieldDNP3Source,
	fieldDNP3IsBroadcast,
	fieldDNP3IsSelfAddress,
	fieldDNP3ApplicationSeq,
	fieldDNP3ConfirmRequired,
	fieldDNP3Unsolicited,
	fieldFunctionCode,
	fieldDNP3FunctionCodeName,
	fieldDNP3IsCriticalFunction,
	fieldDNP3IsConfigChange,
	fieldDNP3IsAuthentication,
	fieldDNP3InternalIndications,
	fieldDNP3IINBroadcast,
	fieldDNP3IINClass1,
	fieldDNP3IINClass2,
	fieldDNP3IINClass3,
	fieldDNP3IINNeedTime,
	fieldDNP3IINLocalControl,
	fieldDNP3IINDeviceTrouble,
	fieldDNP3IINDeviceRestart,
	fieldDNP3IINNoFuncCodeSupport,
	fieldDNP3IINObjectUnknown,
	fieldDNP3IINParameterError,
	fieldDNP3IINEventBufferOverflow,
	fieldDNP3IINAlreadyExecuting,
	fieldDNP3IINConfigCorrupt,
	fieldDNP3HeaderCRCValid,
	fieldDNP3BlockCRCValid,
	fieldDNP3ObjectsTruncated,
	fieldDNP3Objects,
	fieldDNP3CorrelationStatus,
	fieldDNP3RequestTimestamp,
	fieldDNP3ResponseLatency,
	fieldDNP3SBOStatus,
	fieldDNP3SelectTimestamp,
	fieldDNP3OperateLatency,
}

// CSVHeader returns the CSV header for the audit record.
func (d *DNP3) CSVHeader() []string {
	return filter(fieldsDNP3)
}

// CSVRecord returns the CSV record for the audit record.
func (d *DNP3) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(d.Timestamp),
		d.SrcIP,
		d.DstIP,
		formatInt32(d.SrcPort),
		formatInt32(d.DstPort),
		d.ParseStatus,
		d.ParseError,
		formatInt64(d.LostBytes),
		formatInt32(d.Length),
		formatInt32(d.Control),
		strconv.FormatBool(d.IsMaster),
		strconv.FormatBool(d.IsRequest),
		strconv.FormatBool(d.DirectionMismatch),
		formatInt32(d.LinkFunctionCode),
		d.LinkFunctionCodeName,
		strconv.FormatBool(d.LinkFCB),
		strconv.FormatBool(d.LinkFCV),
		strconv.FormatBool(d.LinkDFC),
		formatInt32(d.Destination),
		formatInt32(d.Source),
		strconv.FormatBool(d.IsBroadcast),
		strconv.FormatBool(d.IsSelfAddress),
		formatInt32(d.ApplicationSeq),
		strconv.FormatBool(d.ConfirmRequired),
		strconv.FormatBool(d.Unsolicited),
		formatInt32(d.FunctionCode),
		d.FunctionCodeName,
		strconv.FormatBool(d.IsCriticalFunction),
		strconv.FormatBool(d.IsConfigChange),
		strconv.FormatBool(d.IsAuthentication),
		formatInt32(d.InternalIndications),
		strconv.FormatBool(d.IINBroadcast),
		strconv.FormatBool(d.IINClass1),
		strconv.FormatBool(d.IINClass2),
		strconv.FormatBool(d.IINClass3),
		strconv.FormatBool(d.IINNeedTime),
		strconv.FormatBool(d.IINLocalControl),
		strconv.FormatBool(d.IINDeviceTrouble),
		strconv.FormatBool(d.IINDeviceRestart),
		strconv.FormatBool(d.IINNoFuncCodeSupport),
		strconv.FormatBool(d.IINObjectUnknown),
		strconv.FormatBool(d.IINParameterError),
		strconv.FormatBool(d.IINEventBufferOverflow),
		strconv.FormatBool(d.IINAlreadyExecuting),
		strconv.FormatBool(d.IINConfigCorrupt),
		strconv.FormatBool(d.HeaderCRCValid),
		strconv.FormatBool(d.BlockCRCValid),
		strconv.FormatBool(d.ObjectsTruncated),
		dnp3JSONCell(d.Objects),
		d.CorrelationStatus,
		formatInt64(d.RequestTimestamp),
		formatInt64(d.ResponseLatency),
		d.SBOStatus,
		formatInt64(d.SelectTimestamp),
		formatInt64(d.OperateLatency),
	})
}

func dnp3JSONCell(value any) string {
	data, _ := json.Marshal(value) // DNP3 slices contain only protobuf scalar/message fields.

	return string(data)
}

// Time returns the timestamp associated with the audit record.
func (d *DNP3) Time() int64 {
	return d.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (d *DNP3) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	d.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(d)
}

// Endpoints, link addresses and object detail are deliberately not labels: one
// series per address pair over a long capture is a cardinality explosion, and
// these are counts of observed frames rather than of executed commands.
var dnp3Metric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_DNP3.String()),
		Help: Type_NC_DNP3.String() + " audit records",
	},
	[]string{fieldDNP3FunctionCodeName, fieldDNP3ParseStatus},
)

// Inc increments the metrics for the audit record.
func (d *DNP3) Inc() {
	dnp3Metric.WithLabelValues(d.FunctionCodeName, d.ParseStatus).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (d *DNP3) SetPacketContext(ctx *PacketContext) {
	d.SrcIP = ctx.SrcIP
	d.DstIP = ctx.DstIP
	d.SrcPort = ctx.SrcPort
	d.DstPort = ctx.DstPort
}

// Src returns the source address of the audit record.
func (d *DNP3) Src() string {
	return d.SrcIP
}

// Dst returns the destination address of the audit record.
func (d *DNP3) Dst() string {
	return d.DstIP
}

var dnp3Encoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (d *DNP3) Encode() []string {
	return filter([]string{
		dnp3Encoder.Int64(fieldTimestamp, d.Timestamp),
		dnp3Encoder.String(fieldSrcIP, d.SrcIP),
		dnp3Encoder.String(fieldDstIP, d.DstIP),
		dnp3Encoder.Int32(fieldSrcPort, d.SrcPort),
		dnp3Encoder.Int32(fieldDstPort, d.DstPort),
		dnp3Encoder.String(fieldDNP3ParseStatus, d.ParseStatus),
		dnp3Encoder.String(fieldDNP3ParseError, d.ParseError),
		dnp3Encoder.Int64(fieldDNP3LostBytes, d.LostBytes),
		dnp3Encoder.Int32(fieldLength, d.Length),
		dnp3Encoder.Int32(fieldDNP3Control, d.Control),
		dnp3Encoder.Bool(d.IsMaster),
		dnp3Encoder.Bool(d.IsRequest),
		dnp3Encoder.Bool(d.DirectionMismatch),
		dnp3Encoder.Int32(fieldDNP3LinkFunctionCode, d.LinkFunctionCode),
		dnp3Encoder.String(fieldDNP3LinkFunctionCodeName, d.LinkFunctionCodeName),
		dnp3Encoder.Bool(d.LinkFCB),
		dnp3Encoder.Bool(d.LinkFCV),
		dnp3Encoder.Bool(d.LinkDFC),
		dnp3Encoder.Int32(fieldDNP3Destination, d.Destination),
		dnp3Encoder.Int32(fieldDNP3Source, d.Source),
		dnp3Encoder.Bool(d.IsBroadcast),
		dnp3Encoder.Bool(d.IsSelfAddress),
		dnp3Encoder.Int32(fieldDNP3ApplicationSeq, d.ApplicationSeq),
		dnp3Encoder.Bool(d.ConfirmRequired),
		dnp3Encoder.Bool(d.Unsolicited),
		dnp3Encoder.Int32(fieldFunctionCode, d.FunctionCode),
		dnp3Encoder.String(fieldDNP3FunctionCodeName, d.FunctionCodeName),
		dnp3Encoder.Bool(d.IsCriticalFunction),
		dnp3Encoder.Bool(d.IsConfigChange),
		dnp3Encoder.Bool(d.IsAuthentication),
		dnp3Encoder.Int32(fieldDNP3InternalIndications, d.InternalIndications),
		dnp3Encoder.Bool(d.IINBroadcast),
		dnp3Encoder.Bool(d.IINClass1),
		dnp3Encoder.Bool(d.IINClass2),
		dnp3Encoder.Bool(d.IINClass3),
		dnp3Encoder.Bool(d.IINNeedTime),
		dnp3Encoder.Bool(d.IINLocalControl),
		dnp3Encoder.Bool(d.IINDeviceTrouble),
		dnp3Encoder.Bool(d.IINDeviceRestart),
		dnp3Encoder.Bool(d.IINNoFuncCodeSupport),
		dnp3Encoder.Bool(d.IINObjectUnknown),
		dnp3Encoder.Bool(d.IINParameterError),
		dnp3Encoder.Bool(d.IINEventBufferOverflow),
		dnp3Encoder.Bool(d.IINAlreadyExecuting),
		dnp3Encoder.Bool(d.IINConfigCorrupt),
		dnp3Encoder.Bool(d.HeaderCRCValid),
		dnp3Encoder.Bool(d.BlockCRCValid),
		dnp3Encoder.Bool(d.ObjectsTruncated),
		dnp3Encoder.String(fieldDNP3Objects, dnp3JSONCell(d.Objects)),
		dnp3Encoder.String(fieldDNP3CorrelationStatus, d.CorrelationStatus),
		dnp3Encoder.Int64(fieldDNP3RequestTimestamp, d.RequestTimestamp),
		dnp3Encoder.Int64(fieldDNP3ResponseLatency, d.ResponseLatency),
		dnp3Encoder.String(fieldDNP3SBOStatus, d.SBOStatus),
		dnp3Encoder.Int64(fieldDNP3SelectTimestamp, d.SelectTimestamp),
		dnp3Encoder.Int64(fieldDNP3OperateLatency, d.OperateLatency),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (d *DNP3) Analyze() {}

// NetcapType returns the type of the current audit record
func (d *DNP3) NetcapType() Type {
	return Type_NC_DNP3
}
