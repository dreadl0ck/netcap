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
	fieldGroupAddresses = "GroupAddresses"
)

var fieldsPIM = []string{
	fieldTimestamp,
	fieldVersion,        // int32
	fieldType,           // int32
	fieldTypeName,       // string
	fieldChecksum,       // int32
	fieldGroupAddresses, // []string
	fieldSrcIP,
	fieldDstIP,
}

// CSVHeader returns the CSV header for the audit record.
func (a *PIM) CSVHeader() []string {
	return filter(fieldsPIM)
}

// CSVRecord returns the CSV record for the audit record.
func (a *PIM) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(a.Timestamp),
		formatInt32(a.Version),          // int32
		formatInt32(a.Type),             // int32
		a.TypeName,                      // string
		formatInt32(a.Checksum),         // int32
		join(a.GroupAddresses...),       // []string
		a.SrcIP,
		a.DstIP,
	})
}

// Time returns the timestamp associated with the audit record.
func (a *PIM) Time() int64 {
	return a.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (a *PIM) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	a.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(a)
}

var pimMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_PIM.String()),
		Help: Type_NC_PIM.String() + " audit records",
	},
	fieldsPIM[1:],
)

// Inc increments the metrics for the audit record.
func (a *PIM) Inc() {
	pimMetric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (a *PIM) SetPacketContext(ctx *PacketContext) {
	a.SrcIP = ctx.SrcIP
	a.DstIP = ctx.DstIP
}

// Src returns the source address of the audit record.
func (a *PIM) Src() string {
	return a.SrcIP
}

// Dst returns the destination address of the audit record.
func (a *PIM) Dst() string {
	return a.DstIP
}

var pimEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (a *PIM) Encode() []string {
	return filter([]string{
		pimEncoder.Int64(fieldTimestamp, a.Timestamp),
		pimEncoder.Int32(fieldVersion, a.Version),                            // int32
		pimEncoder.Int32(fieldType, a.Type),                                  // int32
		pimEncoder.String(fieldTypeName, a.TypeName),                         // string
		pimEncoder.Int32(fieldChecksum, a.Checksum),                          // int32
		pimEncoder.String(fieldGroupAddresses, join(a.GroupAddresses...)),     // []string
		pimEncoder.String(fieldSrcIP, a.SrcIP),
		pimEncoder.String(fieldDstIP, a.DstIP),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (a *PIM) Analyze() {
}

// NetcapType returns the type of the current audit record
func (a *PIM) NetcapType() Type {
	return Type_NC_PIM
}
