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
	fieldServiceName     = "ServiceName"
	fieldIsValid         = "IsValid"
	fieldErrorMsg        = "ErrorMsg"
	fieldDetectionMethod = "DetectionMethod"
	fieldProtoFile       = "ProtoFile"
	fieldFullMessageName = "FullMessageName"
	fieldSchemaResolved  = "SchemaResolved"
)

var fieldsProtobuf = []string{
	fieldTimestamp,
	fieldSrcIP,
	fieldDstIP,
	fieldSrcPort,
	fieldDstPort,
	fieldPayloadSize,
	fieldPayloadEntropy,
	fieldServiceName,
	fieldMessageType,
	fieldIsValid,
	fieldErrorMsg,
	fieldDetectionMethod,
	fieldMessageCount,
	fieldProtoFile,
	fieldFullMessageName,
	fieldSchemaResolved,
}

// CSVHeader returns the CSV header for the audit record.
func (p *Protobuf) CSVHeader() []string {
	return filter(fieldsProtobuf)
}

// CSVRecord returns the CSV record for the audit record.
func (p *Protobuf) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(p.Timestamp),
		p.SrcIP,
		p.DstIP,
		formatInt32(p.SrcPort),
		formatInt32(p.DstPort),
		formatInt32(p.PayloadSize),
		formatFloat64(p.PayloadEntropy),
		p.ServiceName,
		p.MessageType,
		strconv.FormatBool(p.IsValid),
		p.ErrorMsg,
		p.DetectionMethod,
		formatInt32(p.MessageCount),
		p.ProtoFile,
		p.FullMessageName,
		strconv.FormatBool(p.SchemaResolved),
	})
}

// Time returns the timestamp associated with the audit record.
func (p *Protobuf) Time() int64 {
	return p.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (p *Protobuf) JSON() (string, error) {
	p.Timestamp /= int64(time.Millisecond)
	return jsonMarshaler.MarshalToString(p)
}

var protobufMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_Protobuf.String()),
		Help: Type_NC_Protobuf.String() + " audit records",
	},
	fieldsProtobuf[1:],
)

// Inc increments the metrics for the audit record.
func (p *Protobuf) Inc() {
	protobufMetric.WithLabelValues(p.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (p *Protobuf) SetPacketContext(ctx *PacketContext) {
	p.SrcIP = ctx.SrcIP
	p.DstIP = ctx.DstIP
	p.SrcPort = ctx.SrcPort
	p.DstPort = ctx.DstPort
}

// Src returns the source address of the audit record.
func (p *Protobuf) Src() string {
	return p.SrcIP
}

// Dst returns the destination address of the audit record.
func (p *Protobuf) Dst() string {
	return p.DstIP
}

var protobufEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration.
func (p *Protobuf) Encode() []string {
	return filter([]string{
		protobufEncoder.Int64(fieldTimestamp, p.Timestamp),
		protobufEncoder.String(fieldSrcIP, p.SrcIP),
		protobufEncoder.String(fieldDstIP, p.DstIP),
		protobufEncoder.Int32(fieldSrcPort, p.SrcPort),
		protobufEncoder.Int32(fieldDstPort, p.DstPort),
		protobufEncoder.Int32(fieldPayloadSize, p.PayloadSize),
		protobufEncoder.Float64(fieldPayloadEntropy, p.PayloadEntropy),
		protobufEncoder.String(fieldServiceName, p.ServiceName),
		protobufEncoder.String(fieldMessageType, p.MessageType),
		protobufEncoder.Bool(p.IsValid),
		protobufEncoder.String(fieldErrorMsg, p.ErrorMsg),
		protobufEncoder.String(fieldDetectionMethod, p.DetectionMethod),
		protobufEncoder.Int32(fieldMessageCount, p.MessageCount),
		protobufEncoder.String(fieldProtoFile, p.ProtoFile),
		protobufEncoder.String(fieldFullMessageName, p.FullMessageName),
		protobufEncoder.Bool(p.SchemaResolved),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (p *Protobuf) Analyze() {}

// NetcapType returns the type of the current audit record.
func (p *Protobuf) NetcapType() Type {
	return Type_NC_Protobuf
}
