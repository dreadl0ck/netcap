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
	fieldBACnetIPBVLCType                = "BVLCType"
	fieldBACnetIPBVLCFunction            = "BVLCFunction"
	fieldBACnetIPBVLCFunctionName        = "BVLCFunctionName"
	fieldBACnetIPBVLCLength              = "BVLCLength"
	fieldBACnetIPNPDUVersion             = "NPDUVersion"
	fieldBACnetIPNPDUControl             = "NPDUControl"
	fieldBACnetIPNPDUExpectsReply        = "NPDUExpectsReply"
	fieldBACnetIPNPDUNetworkLayerMsg     = "NPDUNetworkLayerMsg"
	fieldBACnetIPNPDUPriority            = "NPDUPriority"
	fieldBACnetIPDNET                    = "DNET"
	fieldBACnetIPDADR                    = "DADR"
	fieldBACnetIPSNET                    = "SNET"
	fieldBACnetIPSADR                    = "SADR"
	fieldBACnetIPHopCount                = "HopCount"
	fieldBACnetIPNetworkMessageType      = "NetworkMessageType"
	fieldBACnetIPNetworkMessageTypeName  = "NetworkMessageTypeName"
	fieldBACnetIPAPDUType                = "APDUType"
	fieldBACnetIPAPDUTypeName            = "APDUTypeName"
	fieldBACnetIPSegmentedMessage        = "SegmentedMessage"
	fieldBACnetIPMoreFollows             = "MoreFollows"
	fieldBACnetIPSegmentedResponseAccepted = "SegmentedResponseAccepted"
	fieldBACnetIPInvokeID                = "InvokeID"
	fieldBACnetIPSequenceNumber          = "SequenceNumber"
	fieldBACnetIPProposedWindowSize      = "ProposedWindowSize"
	fieldBACnetIPServiceChoice           = "ServiceChoice"
	fieldBACnetIPServiceName             = "ServiceName"
	fieldBACnetIPIsConfirmed             = "IsConfirmed"
	fieldBACnetIPErrorClass              = "ErrorClass"
	fieldBACnetIPErrorCode               = "ErrorCode"
	fieldBACnetIPErrorName               = "ErrorName"
	fieldBACnetIPRejectReason            = "RejectReason"
	fieldBACnetIPAbortReason             = "AbortReason"
	fieldBACnetIPObjectType              = "ObjectType"
	fieldBACnetIPObjectTypeName          = "ObjectTypeName"
	fieldBACnetIPObjectInstance          = "ObjectInstance"
	fieldBACnetIPPropertyIdentifier      = "PropertyIdentifier"
	fieldBACnetIPPropertyName            = "PropertyName"
	fieldBACnetIPPropertyArrayIndex      = "PropertyArrayIndex"
	fieldBACnetIPIsSecurityRelevant      = "IsSecurityRelevant"
	fieldBACnetIPIsCriticalOperation     = "IsCriticalOperation"
)

var fieldsBACnetIP = []string{
	fieldTimestamp,
	fieldSrcIP,
	fieldDstIP,
	fieldSrcPort,
	fieldDstPort,
	fieldBACnetIPBVLCType,
	fieldBACnetIPBVLCFunction,
	fieldBACnetIPBVLCFunctionName,
	fieldBACnetIPBVLCLength,
	fieldBACnetIPNPDUVersion,
	fieldBACnetIPNPDUControl,
	fieldBACnetIPNPDUExpectsReply,
	fieldBACnetIPNPDUNetworkLayerMsg,
	fieldBACnetIPNPDUPriority,
	fieldBACnetIPDNET,
	fieldBACnetIPDADR,
	fieldBACnetIPSNET,
	fieldBACnetIPSADR,
	fieldBACnetIPHopCount,
	fieldBACnetIPNetworkMessageType,
	fieldBACnetIPNetworkMessageTypeName,
	fieldBACnetIPAPDUType,
	fieldBACnetIPAPDUTypeName,
	fieldBACnetIPSegmentedMessage,
	fieldBACnetIPMoreFollows,
	fieldBACnetIPSegmentedResponseAccepted,
	fieldBACnetIPInvokeID,
	fieldBACnetIPSequenceNumber,
	fieldBACnetIPProposedWindowSize,
	fieldBACnetIPServiceChoice,
	fieldBACnetIPServiceName,
	fieldBACnetIPIsConfirmed,
	fieldBACnetIPErrorClass,
	fieldBACnetIPErrorCode,
	fieldBACnetIPErrorName,
	fieldBACnetIPRejectReason,
	fieldBACnetIPAbortReason,
	fieldBACnetIPObjectType,
	fieldBACnetIPObjectTypeName,
	fieldBACnetIPObjectInstance,
	fieldBACnetIPPropertyIdentifier,
	fieldBACnetIPPropertyName,
	fieldBACnetIPPropertyArrayIndex,
	fieldBACnetIPIsSecurityRelevant,
	fieldBACnetIPIsCriticalOperation,
}

// CSVHeader returns the CSV header for the audit record.
func (b *BACnetIP) CSVHeader() []string {
	return filter(fieldsBACnetIP)
}

// CSVRecord returns the CSV record for the audit record.
func (b *BACnetIP) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(b.Timestamp),
		b.SrcIP,
		b.DstIP,
		formatInt32(b.SrcPort),
		formatInt32(b.DstPort),
		formatInt32(b.BVLCType),
		formatInt32(b.BVLCFunction),
		b.BVLCFunctionName,
		formatInt32(b.BVLCLength),
		formatInt32(b.NPDUVersion),
		formatInt32(b.NPDUControl),
		strconv.FormatBool(b.NPDUExpectsReply),
		strconv.FormatBool(b.NPDUNetworkLayerMsg),
		formatInt32(b.NPDUPriority),
		formatInt32(b.DNET),
		b.DADR,
		formatInt32(b.SNET),
		b.SADR,
		formatInt32(b.HopCount),
		formatInt32(b.NetworkMessageType),
		b.NetworkMessageTypeName,
		formatInt32(b.APDUType),
		b.APDUTypeName,
		formatInt32(b.SegmentedMessage),
		strconv.FormatBool(b.MoreFollows),
		strconv.FormatBool(b.SegmentedResponseAccepted),
		formatInt32(b.InvokeID),
		formatInt32(b.SequenceNumber),
		formatInt32(b.ProposedWindowSize),
		formatInt32(b.ServiceChoice),
		b.ServiceName,
		strconv.FormatBool(b.IsConfirmed),
		formatInt32(b.ErrorClass),
		formatInt32(b.ErrorCode),
		b.ErrorName,
		formatInt32(b.RejectReason),
		formatInt32(b.AbortReason),
		formatInt32(b.ObjectType),
		b.ObjectTypeName,
		formatUint32(b.ObjectInstance),
		formatInt32(b.PropertyIdentifier),
		b.PropertyName,
		formatInt32(b.PropertyArrayIndex),
		strconv.FormatBool(b.IsSecurityRelevant),
		strconv.FormatBool(b.IsCriticalOperation),
	})
}

// Time returns the timestamp associated with the audit record.
func (b *BACnetIP) Time() int64 {
	return b.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (b *BACnetIP) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	b.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(b)
}

var bacnetipMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_BACnetIP.String()),
		Help: Type_NC_BACnetIP.String() + " audit records",
	},
	fieldsBACnetIP[1:],
)

// Inc increments the metrics for the audit record.
func (b *BACnetIP) Inc() {
	bacnetipMetric.WithLabelValues(b.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (b *BACnetIP) SetPacketContext(ctx *PacketContext) {
	b.SrcIP = ctx.SrcIP
	b.DstIP = ctx.DstIP
	b.SrcPort = ctx.SrcPort
	b.DstPort = ctx.DstPort
}

// Src returns the source address of the audit record.
func (b *BACnetIP) Src() string {
	return b.SrcIP
}

// Dst returns the destination address of the audit record.
func (b *BACnetIP) Dst() string {
	return b.DstIP
}

var bacnetipEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration.
func (b *BACnetIP) Encode() []string {
	return filter([]string{
		bacnetipEncoder.Int64(fieldTimestamp, b.Timestamp),
		bacnetipEncoder.String(fieldSrcIP, b.SrcIP),
		bacnetipEncoder.String(fieldDstIP, b.DstIP),
		bacnetipEncoder.Int32(fieldSrcPort, b.SrcPort),
		bacnetipEncoder.Int32(fieldDstPort, b.DstPort),
		bacnetipEncoder.Int32(fieldBACnetIPBVLCType, b.BVLCType),
		bacnetipEncoder.Int32(fieldBACnetIPBVLCFunction, b.BVLCFunction),
		bacnetipEncoder.String(fieldBACnetIPBVLCFunctionName, b.BVLCFunctionName),
		bacnetipEncoder.Int32(fieldBACnetIPBVLCLength, b.BVLCLength),
		bacnetipEncoder.Int32(fieldBACnetIPNPDUVersion, b.NPDUVersion),
		bacnetipEncoder.Int32(fieldBACnetIPNPDUControl, b.NPDUControl),
		bacnetipEncoder.Bool(b.NPDUExpectsReply),
		bacnetipEncoder.Bool(b.NPDUNetworkLayerMsg),
		bacnetipEncoder.Int32(fieldBACnetIPNPDUPriority, b.NPDUPriority),
		bacnetipEncoder.Int32(fieldBACnetIPDNET, b.DNET),
		bacnetipEncoder.String(fieldBACnetIPDADR, b.DADR),
		bacnetipEncoder.Int32(fieldBACnetIPSNET, b.SNET),
		bacnetipEncoder.String(fieldBACnetIPSADR, b.SADR),
		bacnetipEncoder.Int32(fieldBACnetIPHopCount, b.HopCount),
		bacnetipEncoder.Int32(fieldBACnetIPNetworkMessageType, b.NetworkMessageType),
		bacnetipEncoder.String(fieldBACnetIPNetworkMessageTypeName, b.NetworkMessageTypeName),
		bacnetipEncoder.Int32(fieldBACnetIPAPDUType, b.APDUType),
		bacnetipEncoder.String(fieldBACnetIPAPDUTypeName, b.APDUTypeName),
		bacnetipEncoder.Int32(fieldBACnetIPSegmentedMessage, b.SegmentedMessage),
		bacnetipEncoder.Bool(b.MoreFollows),
		bacnetipEncoder.Bool(b.SegmentedResponseAccepted),
		bacnetipEncoder.Int32(fieldBACnetIPInvokeID, b.InvokeID),
		bacnetipEncoder.Int32(fieldBACnetIPSequenceNumber, b.SequenceNumber),
		bacnetipEncoder.Int32(fieldBACnetIPProposedWindowSize, b.ProposedWindowSize),
		bacnetipEncoder.Int32(fieldBACnetIPServiceChoice, b.ServiceChoice),
		bacnetipEncoder.String(fieldBACnetIPServiceName, b.ServiceName),
		bacnetipEncoder.Bool(b.IsConfirmed),
		bacnetipEncoder.Int32(fieldBACnetIPErrorClass, b.ErrorClass),
		bacnetipEncoder.Int32(fieldBACnetIPErrorCode, b.ErrorCode),
		bacnetipEncoder.String(fieldBACnetIPErrorName, b.ErrorName),
		bacnetipEncoder.Int32(fieldBACnetIPRejectReason, b.RejectReason),
		bacnetipEncoder.Int32(fieldBACnetIPAbortReason, b.AbortReason),
		bacnetipEncoder.Int32(fieldBACnetIPObjectType, b.ObjectType),
		bacnetipEncoder.String(fieldBACnetIPObjectTypeName, b.ObjectTypeName),
		bacnetipEncoder.Uint32(fieldBACnetIPObjectInstance, b.ObjectInstance),
		bacnetipEncoder.Int32(fieldBACnetIPPropertyIdentifier, b.PropertyIdentifier),
		bacnetipEncoder.String(fieldBACnetIPPropertyName, b.PropertyName),
		bacnetipEncoder.Int32(fieldBACnetIPPropertyArrayIndex, b.PropertyArrayIndex),
		bacnetipEncoder.Bool(b.IsSecurityRelevant),
		bacnetipEncoder.Bool(b.IsCriticalOperation),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (b *BACnetIP) Analyze() {}

// NetcapType returns the type of the current audit record.
func (b *BACnetIP) NetcapType() Type {
	return Type_NC_BACnetIP
}

