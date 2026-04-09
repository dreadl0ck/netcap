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
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/encoder"

	"github.com/prometheus/client_golang/prometheus"
)

// fieldOperationName is already defined in ipp.go
// All other field constants reused from arp.go

var fieldsRARP = []string{
	fieldTimestamp,
	fieldAddrType,            // int32
	fieldProtocol,            // int32
	fieldHwAddressSize,       // int32
	fieldProtocolAddressSize, // int32
	fieldOperation,           // int32
	fieldOperationName,       // string
	fieldSrcHwAddress,        // string
	fieldSrcProtocolAddress,  // string
	fieldDstHwAddress,        // string
	fieldDstProtocolAddress,  // string
}

// CSVHeader returns the CSV header for the audit record.
func (a *RARP) CSVHeader() []string {
	return filter(fieldsRARP)
}

// CSVRecord returns the CSV record for the audit record.
func (a *RARP) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(a.Timestamp),
		formatInt32(a.AddrType),            // int32
		formatInt32(a.Protocol),            // int32
		formatInt32(a.HwAddressSize),       // int32
		formatInt32(a.ProtocolAddressSize), // int32
		formatInt32(a.Operation),           // int32
		a.OperationName,                    // string
		a.SrcHwAddress,                     // string
		a.SrcProtocolAddress,               // string
		a.DstHwAddress,                     // string
		a.DstProtocolAddress,               // string
	})
}

// Time returns the timestamp associated with the audit record.
func (a *RARP) Time() int64 {
	return a.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (a *RARP) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	a.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(a)
}

var rarpMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_RARP.String()),
		Help: Type_NC_RARP.String() + " audit records",
	},
	fieldsRARP[1:],
)

// Inc increments the metrics for the audit record.
func (a *RARP) Inc() {
	rarpMetric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (a *RARP) SetPacketContext(_ *PacketContext) {
}

// Src returns the source address of the audit record.
func (a *RARP) Src() string {
	return a.SrcHwAddress
}

// Dst returns the destination address of the audit record.
func (a *RARP) Dst() string {
	return a.DstHwAddress
}

var rarpEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (a *RARP) Encode() []string {
	return filter([]string{
		rarpEncoder.Int64(fieldTimestamp, a.Timestamp),
		rarpEncoder.Int32(fieldAddrType, a.AddrType),                       // int32
		rarpEncoder.Int32(fieldProtocol, a.Protocol),                       // int32
		rarpEncoder.Int32(fieldHwAddressSize, a.HwAddressSize),             // int32
		rarpEncoder.Int32(fieldProtocolAddressSize, a.ProtocolAddressSize), // int32
		rarpEncoder.Int32(fieldOperation, a.Operation),                     // int32
		rarpEncoder.String(fieldOperationName, a.OperationName),            // string
		rarpEncoder.String(fieldSrcHwAddress, a.SrcHwAddress),              // string
		rarpEncoder.String(fieldSrcProtocolAddress, a.SrcProtocolAddress),  // string
		rarpEncoder.String(fieldDstHwAddress, a.DstHwAddress),              // string
		rarpEncoder.String(fieldDstProtocolAddress, a.DstProtocolAddress),  // string
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (a *RARP) Analyze() {
}

// NetcapType returns the type of the current audit record
func (a *RARP) NetcapType() Type {
	return Type_NC_RARP
}
