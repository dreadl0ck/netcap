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
	fieldPacketType     = "PacketType"
	fieldPacketTypeName = "PacketTypeName"
	fieldFragLength     = "FragLength"
	fieldInterfaceUUID  = "InterfaceUUID"
	fieldInterfaceName  = "InterfaceName"
	fieldOpNum          = "OpNum"
)

var fieldsDCERPC = []string{
	fieldTimestamp,
	fieldVersion,        // int32
	fieldVersionMinor,   // int32
	fieldPacketType,     // int32
	fieldPacketTypeName, // string
	fieldFlags,          // int32
	fieldFragLength,     // int32
	fieldCallID,         // int32
	fieldInterfaceUUID,  // string
	fieldInterfaceName,  // string
	fieldOpNum,          // int32
	fieldFlow,
	fieldSrcIP,
	fieldDstIP,
	fieldSrcPort,
	fieldDstPort,
}

// CSVHeader returns the CSV header for the audit record.
func (a *DCERPC) CSVHeader() []string {
	return filter(fieldsDCERPC)
}

// CSVRecord returns the CSV record for the audit record.
func (a *DCERPC) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(a.Timestamp),
		formatInt32(a.Version),      // int32
		formatInt32(a.VersionMinor), // int32
		formatInt32(a.PacketType),   // int32
		a.PacketTypeName,            // string
		formatInt32(a.Flags),        // int32
		formatInt32(a.FragLength),   // int32
		formatInt32(a.CallID),       // int32
		a.InterfaceUUID,             // string
		a.InterfaceName,             // string
		formatInt32(a.OpNum),        // int32
		a.Flow,
		a.SrcIP,
		a.DstIP,
		formatInt32(a.SrcPort),
		formatInt32(a.DstPort),
	})
}

// Time returns the timestamp associated with the audit record.
func (a *DCERPC) Time() int64 {
	return a.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (a *DCERPC) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	a.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(a)
}

var dcerpcMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_DCERPC.String()),
		Help: Type_NC_DCERPC.String() + " audit records",
	},
	fieldsDCERPC[1:],
)

// Inc increments the metrics for the audit record.
func (a *DCERPC) Inc() {
	dcerpcMetric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (a *DCERPC) SetPacketContext(*PacketContext) {}

// Src returns the source address of the audit record.
func (a *DCERPC) Src() string {
	return a.SrcIP
}

// Dst returns the destination address of the audit record.
func (a *DCERPC) Dst() string {
	return a.DstIP
}

var dcerpcEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (a *DCERPC) Encode() []string {
	return filter([]string{
		dcerpcEncoder.Int64(fieldTimestamp, a.Timestamp),
		dcerpcEncoder.Int32(fieldVersion, a.Version),              // int32
		dcerpcEncoder.Int32(fieldVersionMinor, a.VersionMinor),    // int32
		dcerpcEncoder.Int32(fieldPacketType, a.PacketType),        // int32
		dcerpcEncoder.String(fieldPacketTypeName, a.PacketTypeName), // string
		dcerpcEncoder.Int32(fieldFlags, a.Flags),                  // int32
		dcerpcEncoder.Int32(fieldFragLength, a.FragLength),        // int32
		dcerpcEncoder.Int32(fieldCallID, a.CallID),                // int32
		dcerpcEncoder.String(fieldInterfaceUUID, a.InterfaceUUID), // string
		dcerpcEncoder.String(fieldInterfaceName, a.InterfaceName), // string
		dcerpcEncoder.Int32(fieldOpNum, a.OpNum),                  // int32
		dcerpcEncoder.String(fieldFlow, a.Flow),
		dcerpcEncoder.String(fieldSrcIP, a.SrcIP),
		dcerpcEncoder.String(fieldDstIP, a.DstIP),
		dcerpcEncoder.Int32(fieldSrcPort, a.SrcPort),
		dcerpcEncoder.Int32(fieldDstPort, a.DstPort),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (a *DCERPC) Analyze() {
}

// NetcapType returns the type of the current audit record
func (a *DCERPC) NetcapType() Type {
	return Type_NC_DCERPC
}
