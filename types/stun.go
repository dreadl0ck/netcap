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
	"strconv"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/encoder"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	fieldMessageType   = "MessageType"
	fieldMessageLength = "MessageLength"
	fieldMessageClass  = "MessageClass"
	fieldMappedAddress = "MappedAddress"
	fieldIsRFC5389  = "IsRFC5389"
	fieldAttributes = "Attributes"
)

var fieldsSTUN = []string{
	fieldTimestamp,
	fieldMessageType,   // int32
	fieldMessageLength, // int32
	fieldTransactionID, // []byte
	fieldMessageClass,  // string
	fieldMethod,        // string
	fieldMappedAddress, // string
	fieldSrcIP,
	fieldDstIP,
	fieldSrcPort,
	fieldDstPort,
	fieldIsRFC5389,  // bool
	fieldAttributes, // []*STUNAttribute
}

// CSVHeader returns the CSV header for the audit record.
func (a *STUN) CSVHeader() []string {
	return filter(fieldsSTUN)
}

// CSVRecord returns the CSV record for the audit record.
func (a *STUN) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(a.Timestamp),
		formatInt32(a.MessageType),              // int32
		formatInt32(a.MessageLength),            // int32
		hex.EncodeToString(a.TransactionID),     // []byte
		a.MessageClass,                          // string
		a.Method,                                // string
		a.MappedAddress,                         // string
		a.SrcIP,
		a.DstIP,
		formatInt32(a.SrcPort),
		formatInt32(a.DstPort),
		strconv.FormatBool(a.IsRFC5389),         // bool
		formatInt32(int32(len(a.Attributes))),   // []*STUNAttribute
	})
}

// Time returns the timestamp associated with the audit record.
func (a *STUN) Time() int64 {
	return a.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (a *STUN) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	a.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(a)
}

var stunMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_STUN.String()),
		Help: Type_NC_STUN.String() + " audit records",
	},
	fieldsSTUN[1:],
)

// Inc increments the metrics for the audit record.
func (a *STUN) Inc() {
	stunMetric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (a *STUN) SetPacketContext(ctx *PacketContext) {
	a.SrcIP = ctx.SrcIP
	a.DstIP = ctx.DstIP
}

// Src returns the source address of the audit record.
func (a *STUN) Src() string {
	return a.SrcIP
}

// Dst returns the destination address of the audit record.
func (a *STUN) Dst() string {
	return a.DstIP
}

var stunEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (a *STUN) Encode() []string {
	return filter([]string{
		stunEncoder.Int64(fieldTimestamp, a.Timestamp),
		stunEncoder.Int32(fieldMessageType, a.MessageType),              // int32
		stunEncoder.Int32(fieldMessageLength, a.MessageLength),          // int32
		stunEncoder.String(fieldTransactionID, hex.EncodeToString(a.TransactionID)), // []byte
		stunEncoder.String(fieldMessageClass, a.MessageClass),           // string
		stunEncoder.String(fieldMethod, a.Method),                       // string
		stunEncoder.String(fieldMappedAddress, a.MappedAddress),         // string
		stunEncoder.String(fieldSrcIP, a.SrcIP),
		stunEncoder.String(fieldDstIP, a.DstIP),
		stunEncoder.Int32(fieldSrcPort, a.SrcPort),
		stunEncoder.Int32(fieldDstPort, a.DstPort),
		stunEncoder.Bool(a.IsRFC5389),                                   // bool
		stunEncoder.Int32(fieldAttributes, int32(len(a.Attributes))),    // []*STUNAttribute
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (a *STUN) Analyze() {
}

// NetcapType returns the type of the current audit record
func (a *STUN) NetcapType() Type {
	return Type_NC_STUN
}
