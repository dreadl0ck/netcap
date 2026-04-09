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
	fieldOPCUAMessageType         = "MessageType"
	fieldOPCUAChunkType           = "ChunkType"
	fieldOPCUAMessageSize         = "MessageSize"
	fieldOPCUAProtocolVersion     = "ProtocolVersion"
	fieldOPCUAReceiveBufferSize   = "ReceiveBufferSize"
	fieldOPCUASendBufferSize      = "SendBufferSize"
	fieldOPCUAMaxMessageSize      = "MaxMessageSize"
	fieldOPCUAMaxChunkCount       = "MaxChunkCount"
	fieldOPCUAEndpointUrl         = "EndpointUrl"
	fieldOPCUAErrorCode           = "ErrorCode"
	fieldOPCUAErrorReason         = "ErrorReason"
	fieldOPCUASecureChannelId     = "SecureChannelId"
	fieldOPCUASecurityPolicyUri   = "SecurityPolicyUri"
	fieldOPCUASecurityMode        = "SecurityMode"
	fieldOPCUARequestId           = "RequestId"
	fieldOPCUASequenceNumber      = "SequenceNumber"
	fieldOPCUAServiceNodeId       = "ServiceNodeId"
	fieldOPCUAServiceName         = "ServiceName"
	fieldOPCUAIsRequest           = "IsRequest"
	fieldOPCUARequestHandle       = "RequestHandle"
	fieldOPCUAStatusCode          = "StatusCode"
	fieldOPCUAStatusCodeName      = "StatusCodeName"
	fieldOPCUASessionId           = "SessionId"
	fieldOPCUAAuthenticationToken = "AuthenticationToken"
	fieldOPCUAIsSecurityRelevant  = "IsSecurityRelevant"
	fieldOPCUAIsCriticalOperation = "IsCriticalOperation"
)

var fieldsOPCUA = []string{
	fieldTimestamp,
	fieldSrcIP,
	fieldDstIP,
	fieldSrcPort,
	fieldDstPort,
	fieldOPCUAMessageType,
	fieldOPCUAChunkType,
	fieldOPCUAMessageSize,
	fieldOPCUAProtocolVersion,
	fieldOPCUAReceiveBufferSize,
	fieldOPCUASendBufferSize,
	fieldOPCUAMaxMessageSize,
	fieldOPCUAMaxChunkCount,
	fieldOPCUAEndpointUrl,
	fieldOPCUAErrorCode,
	fieldOPCUAErrorReason,
	fieldOPCUASecureChannelId,
	fieldOPCUASecurityPolicyUri,
	fieldOPCUASecurityMode,
	fieldOPCUARequestId,
	fieldOPCUASequenceNumber,
	fieldOPCUAServiceNodeId,
	fieldOPCUAServiceName,
	fieldOPCUAIsRequest,
	fieldOPCUARequestHandle,
	fieldOPCUAStatusCode,
	fieldOPCUAStatusCodeName,
	fieldOPCUASessionId,
	fieldOPCUAAuthenticationToken,
	fieldOPCUAIsSecurityRelevant,
	fieldOPCUAIsCriticalOperation,
}

// CSVHeader returns the CSV header for the audit record.
func (o *OPCUA) CSVHeader() []string {
	return filter(fieldsOPCUA)
}

// CSVRecord returns the CSV record for the audit record.
func (o *OPCUA) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(o.Timestamp),
		o.SrcIP,
		o.DstIP,
		formatInt32(o.SrcPort),
		formatInt32(o.DstPort),
		o.MessageType,
		o.ChunkType,
		formatInt32(o.MessageSize),
		formatInt32(o.ProtocolVersion),
		formatInt32(o.ReceiveBufferSize),
		formatInt32(o.SendBufferSize),
		formatInt32(o.MaxMessageSize),
		formatInt32(o.MaxChunkCount),
		o.EndpointUrl,
		formatUint32(o.ErrorCode),
		o.ErrorReason,
		formatUint32(o.SecureChannelId),
		o.SecurityPolicyUri,
		o.SecurityMode,
		formatUint32(o.RequestId),
		formatUint32(o.SequenceNumber),
		o.ServiceNodeId,
		o.ServiceName,
		strconv.FormatBool(o.IsRequest),
		formatUint32(o.RequestHandle),
		formatUint32(o.StatusCode),
		o.StatusCodeName,
		o.SessionId,
		o.AuthenticationToken,
		strconv.FormatBool(o.IsSecurityRelevant),
		strconv.FormatBool(o.IsCriticalOperation),
	})
}

// Time returns the timestamp associated with the audit record.
func (o *OPCUA) Time() int64 {
	return o.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (o *OPCUA) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	o.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(o)
}

var opcuaMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_OPCUA.String()),
		Help: Type_NC_OPCUA.String() + " audit records",
	},
	fieldsOPCUA[1:],
)

// Inc increments the metrics for the audit record.
func (o *OPCUA) Inc() {
	opcuaMetric.WithLabelValues(o.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (o *OPCUA) SetPacketContext(ctx *PacketContext) {
	o.SrcIP = ctx.SrcIP
	o.DstIP = ctx.DstIP
	o.SrcPort = ctx.SrcPort
	o.DstPort = ctx.DstPort
}

// Src returns the source address of the audit record.
func (o *OPCUA) Src() string {
	return o.SrcIP
}

// Dst returns the destination address of the audit record.
func (o *OPCUA) Dst() string {
	return o.DstIP
}

var opcuaEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration.
func (o *OPCUA) Encode() []string {
	return filter([]string{
		opcuaEncoder.Int64(fieldTimestamp, o.Timestamp),
		opcuaEncoder.String(fieldSrcIP, o.SrcIP),
		opcuaEncoder.String(fieldDstIP, o.DstIP),
		opcuaEncoder.Int32(fieldSrcPort, o.SrcPort),
		opcuaEncoder.Int32(fieldDstPort, o.DstPort),
		opcuaEncoder.String(fieldOPCUAMessageType, o.MessageType),
		opcuaEncoder.String(fieldOPCUAChunkType, o.ChunkType),
		opcuaEncoder.Int32(fieldOPCUAMessageSize, o.MessageSize),
		opcuaEncoder.Int32(fieldOPCUAProtocolVersion, o.ProtocolVersion),
		opcuaEncoder.Int32(fieldOPCUAReceiveBufferSize, o.ReceiveBufferSize),
		opcuaEncoder.Int32(fieldOPCUASendBufferSize, o.SendBufferSize),
		opcuaEncoder.Int32(fieldOPCUAMaxMessageSize, o.MaxMessageSize),
		opcuaEncoder.Int32(fieldOPCUAMaxChunkCount, o.MaxChunkCount),
		opcuaEncoder.String(fieldOPCUAEndpointUrl, o.EndpointUrl),
		opcuaEncoder.Uint32(fieldOPCUAErrorCode, o.ErrorCode),
		opcuaEncoder.String(fieldOPCUAErrorReason, o.ErrorReason),
		opcuaEncoder.Uint32(fieldOPCUASecureChannelId, o.SecureChannelId),
		opcuaEncoder.String(fieldOPCUASecurityPolicyUri, o.SecurityPolicyUri),
		opcuaEncoder.String(fieldOPCUASecurityMode, o.SecurityMode),
		opcuaEncoder.Uint32(fieldOPCUARequestId, o.RequestId),
		opcuaEncoder.Uint32(fieldOPCUASequenceNumber, o.SequenceNumber),
		opcuaEncoder.String(fieldOPCUAServiceNodeId, o.ServiceNodeId),
		opcuaEncoder.String(fieldOPCUAServiceName, o.ServiceName),
		opcuaEncoder.Bool(o.IsRequest),
		opcuaEncoder.Uint32(fieldOPCUARequestHandle, o.RequestHandle),
		opcuaEncoder.Uint32(fieldOPCUAStatusCode, o.StatusCode),
		opcuaEncoder.String(fieldOPCUAStatusCodeName, o.StatusCodeName),
		opcuaEncoder.String(fieldOPCUASessionId, o.SessionId),
		opcuaEncoder.String(fieldOPCUAAuthenticationToken, o.AuthenticationToken),
		opcuaEncoder.Bool(o.IsSecurityRelevant),
		opcuaEncoder.Bool(o.IsCriticalOperation),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (o *OPCUA) Analyze() {}

// NetcapType returns the type of the current audit record.
func (o *OPCUA) NetcapType() Type {
	return Type_NC_OPCUA
}
