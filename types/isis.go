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

const (
	fieldPDUType       = "PDUType"
	fieldPDUTypeName   = "PDUTypeName"
	fieldSystemID      = "SystemID"
	fieldHoldingTime   = "HoldingTime"
	fieldCircuitType   = "CircuitType"
	fieldAreaAddresses = "AreaAddresses"
	fieldPDULength     = "PDULength"
)

var fieldsISIS = []string{
	fieldTimestamp,
	fieldPDUType,       // int32
	fieldPDUTypeName,   // string
	fieldSystemID,      // string
	fieldHoldingTime,   // int32
	fieldCircuitType,   // int32
	fieldAreaAddresses, // []string
	fieldSrcMAC,
	fieldDstMAC,
	fieldPDULength, // int32
	fieldVersion,   // int32
}

// CSVHeader returns the CSV header for the audit record.
func (a *ISIS) CSVHeader() []string {
	return filter(fieldsISIS)
}

// CSVRecord returns the CSV record for the audit record.
func (a *ISIS) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(a.Timestamp),
		formatInt32(a.PDUType),       // int32
		a.PDUTypeName,                // string
		a.SystemID,                   // string
		formatInt32(a.HoldingTime),   // int32
		formatInt32(a.CircuitType),   // int32
		join(a.AreaAddresses...),     // []string
		a.SrcMAC,
		a.DstMAC,
		formatInt32(a.PDULength), // int32
		formatInt32(a.Version),  // int32
	})
}

// Time returns the timestamp associated with the audit record.
func (a *ISIS) Time() int64 {
	return a.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (a *ISIS) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	a.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(a)
}

var isisMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_ISIS.String()),
		Help: Type_NC_ISIS.String() + " audit records",
	},
	fieldsISIS[1:],
)

// Inc increments the metrics for the audit record.
func (a *ISIS) Inc() {
	isisMetric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (a *ISIS) SetPacketContext(_ *PacketContext) {
}

// Src returns the source address of the audit record.
func (a *ISIS) Src() string {
	return a.SrcMAC
}

// Dst returns the destination address of the audit record.
func (a *ISIS) Dst() string {
	return a.DstMAC
}

var isisEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (a *ISIS) Encode() []string {
	return filter([]string{
		isisEncoder.Int64(fieldTimestamp, a.Timestamp),
		isisEncoder.Int32(fieldPDUType, a.PDUType),                       // int32
		isisEncoder.String(fieldPDUTypeName, a.PDUTypeName),              // string
		isisEncoder.String(fieldSystemID, a.SystemID),                    // string
		isisEncoder.Int32(fieldHoldingTime, a.HoldingTime),               // int32
		isisEncoder.Int32(fieldCircuitType, a.CircuitType),               // int32
		isisEncoder.String(fieldAreaAddresses, join(a.AreaAddresses...)), // []string
		isisEncoder.String(fieldSrcMAC, a.SrcMAC),
		isisEncoder.String(fieldDstMAC, a.DstMAC),
		isisEncoder.Int32(fieldPDULength, a.PDULength), // int32
		isisEncoder.Int32(fieldVersion, a.Version),     // int32
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (a *ISIS) Analyze() {
}

// NetcapType returns the type of the current audit record
func (a *ISIS) NetcapType() Type {
	return Type_NC_ISIS
}
