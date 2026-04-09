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
	fieldSessionId            = "SessionId"
	fieldCodeName             = "CodeName"
	fieldIsDiscovery          = "IsDiscovery"
	fieldIsSessionTermination = "IsSessionTermination"
	fieldIsSessionEstablished = "IsSessionEstablished"
)

var fieldsPPPoE = []string{
	fieldTimestamp,
	fieldVersion,              // int32
	fieldType,                 // int32
	fieldCode,                 // int32
	fieldCodeName,             // string
	fieldSessionId,            // int32
	fieldLength,               // int32
	fieldIsDiscovery,          // bool
	fieldIsSessionTermination, // bool
	fieldIsSessionEstablished, // bool
}

// CSVHeader returns the CSV header for the audit record.
func (p *PPPoE) CSVHeader() []string {
	return filter(fieldsPPPoE)
}

// CSVRecord returns the CSV record for the audit record.
func (p *PPPoE) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(p.Timestamp),
		formatInt32(p.Version),                     // int32
		formatInt32(p.Type),                        // int32
		formatInt32(p.Code),                        // int32
		p.CodeName,                                 // string
		formatInt32(p.SessionId),                   // int32
		formatInt32(p.Length),                      // int32
		strconv.FormatBool(p.IsDiscovery),          // bool
		strconv.FormatBool(p.IsSessionTermination), // bool
		strconv.FormatBool(p.IsSessionEstablished), // bool
	})
}

// Time returns the timestamp associated with the audit record.
func (p *PPPoE) Time() int64 {
	return p.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (p *PPPoE) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	p.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(p)
}

var pppoeMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_PPPoE.String()),
		Help: Type_NC_PPPoE.String() + " audit records",
	},
	fieldsPPPoE[1:],
)

// Inc increments the metrics for the audit record.
func (p *PPPoE) Inc() {
	pppoeMetric.WithLabelValues(p.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (p *PPPoE) SetPacketContext(*PacketContext) {}

// Src returns the source address of the audit record.
func (p *PPPoE) Src() string {
	return ""
}

// Dst returns the destination address of the audit record.
func (p *PPPoE) Dst() string {
	return ""
}

var pppoeEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (p *PPPoE) Encode() []string {
	return filter([]string{
		pppoeEncoder.Int64(fieldTimestamp, p.Timestamp),
		pppoeEncoder.Int32(fieldVersion, p.Version),     // int32
		pppoeEncoder.Int32(fieldType, p.Type),           // int32
		pppoeEncoder.Int32(fieldCode, p.Code),           // int32
		pppoeEncoder.String(fieldCodeName, p.CodeName),  // string
		pppoeEncoder.Int32(fieldSessionId, p.SessionId), // int32
		pppoeEncoder.Int32(fieldLength, p.Length),       // int32
		pppoeEncoder.Bool(p.IsDiscovery),                // bool
		pppoeEncoder.Bool(p.IsSessionTermination),       // bool
		pppoeEncoder.Bool(p.IsSessionEstablished),       // bool
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (p *PPPoE) Analyze() {}

// NetcapType returns the type of the current audit record
func (p *PPPoE) NetcapType() Type {
	return Type_NC_PPPoE
}
