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
	// fieldVersionMajor and fieldVersionMinor are declared in ipp.go
	fieldAction     = "Action"
	fieldRemoteAddr = "RemoteAddr"
	fieldStatusName = "StatusName"
)

var fieldsTACACS = []string{
	fieldTimestamp,
	fieldVersionMajor,   // int32
	fieldVersionMinor,   // int32
	fieldType,           // int32
	fieldTypeName,       // string
	fieldSequenceNumber, // int32
	fieldFlags,          // int32
	fieldSessionID,      // int32
	fieldLength,         // int32
	fieldAction,         // string
	fieldUser,           // string
	fieldRemoteAddr,     // string
	fieldService,        // string
	fieldStatus,         // int32
	fieldStatusName,     // string
	fieldFlow,
	fieldSrcIP,
	fieldDstIP,
	fieldSrcPort,
	fieldDstPort,
}

// CSVHeader returns the CSV header for the audit record.
func (a *TACACS) CSVHeader() []string {
	return filter(fieldsTACACS)
}

// CSVRecord returns the CSV record for the audit record.
func (a *TACACS) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(a.Timestamp),
		formatInt32(a.VersionMajor),   // int32
		formatInt32(a.VersionMinor),   // int32
		formatInt32(a.Type),           // int32
		a.TypeName,                    // string
		formatInt32(a.SequenceNumber), // int32
		formatInt32(a.Flags),          // int32
		formatInt32(a.SessionID),      // int32
		formatInt32(a.Length),         // int32
		a.Action,                      // string
		a.User,                        // string
		a.RemoteAddr,                  // string
		a.Service,                     // string
		formatInt32(a.Status),         // int32
		a.StatusName,                  // string
		a.Flow,
		a.SrcIP,
		a.DstIP,
		formatInt32(a.SrcPort),
		formatInt32(a.DstPort),
	})
}

// Time returns the timestamp associated with the audit record.
func (a *TACACS) Time() int64 {
	return a.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (a *TACACS) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	a.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(a)
}

var tacacsMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_TACACS.String()),
		Help: Type_NC_TACACS.String() + " audit records",
	},
	fieldsTACACS[1:],
)

// Inc increments the metrics for the audit record.
func (a *TACACS) Inc() {
	tacacsMetric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (a *TACACS) SetPacketContext(_ *PacketContext) {
}

// Src returns the source address of the audit record.
func (a *TACACS) Src() string {
	return a.SrcIP
}

// Dst returns the destination address of the audit record.
func (a *TACACS) Dst() string {
	return a.DstIP
}

var tacacsEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (a *TACACS) Encode() []string {
	return filter([]string{
		tacacsEncoder.Int64(fieldTimestamp, a.Timestamp),
		tacacsEncoder.Int32(fieldVersionMajor, a.VersionMajor),     // int32
		tacacsEncoder.Int32(fieldVersionMinor, a.VersionMinor),     // int32
		tacacsEncoder.Int32(fieldType, a.Type),                     // int32
		tacacsEncoder.String(fieldTypeName, a.TypeName),            // string
		tacacsEncoder.Int32(fieldSequenceNumber, a.SequenceNumber), // int32
		tacacsEncoder.Int32(fieldFlags, a.Flags),                   // int32
		tacacsEncoder.Int32(fieldSessionID, a.SessionID),           // int32
		tacacsEncoder.Int32(fieldLength, a.Length),                  // int32
		tacacsEncoder.String(fieldAction, a.Action),                // string
		tacacsEncoder.String(fieldUser, a.User),                    // string
		tacacsEncoder.String(fieldRemoteAddr, a.RemoteAddr),        // string
		tacacsEncoder.String(fieldService, a.Service),              // string
		tacacsEncoder.Int32(fieldStatus, a.Status),                 // int32
		tacacsEncoder.String(fieldStatusName, a.StatusName),        // string
		tacacsEncoder.String(fieldFlow, a.Flow),
		tacacsEncoder.String(fieldSrcIP, a.SrcIP),
		tacacsEncoder.String(fieldDstIP, a.DstIP),
		tacacsEncoder.Int32(fieldSrcPort, a.SrcPort),
		tacacsEncoder.Int32(fieldDstPort, a.DstPort),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (a *TACACS) Analyze() {
}

// NetcapType returns the type of the current audit record
func (a *TACACS) NetcapType() Type {
	return Type_NC_TACACS
}
