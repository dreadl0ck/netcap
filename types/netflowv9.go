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
	fieldCount      = "Count"
	fieldSysUptime  = "SysUptime"
	fieldUnixSecs   = "UnixSecs"
	fieldSourceID   = "SourceID"
	fieldIsTemplate = "IsTemplate"
	fieldFlowSets   = "FlowSets"
)

var fieldsNetFlowV9 = []string{
	fieldTimestamp,
	fieldVersion,        // int32
	fieldCount,          // int32
	fieldSysUptime,      // int64
	fieldUnixSecs,       // int64
	fieldSequenceNumber, // int32
	fieldSourceID,       // int32
	fieldIsTemplate,     // bool
	fieldFlowSets,       // []*NetFlowV9FlowSet
	fieldSrcIP,
	fieldDstIP,
}

// CSVHeader returns the CSV header for the audit record.
func (a *NetFlowV9) CSVHeader() []string {
	return filter(fieldsNetFlowV9)
}

// CSVRecord returns the CSV record for the audit record.
func (a *NetFlowV9) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(a.Timestamp),
		formatInt32(a.Version),                      // int32
		formatInt32(a.Count),                        // int32
		formatInt64(a.SysUptime),                    // int64
		formatInt64(a.UnixSecs),                     // int64
		formatInt32(a.SequenceNumber),               // int32
		formatInt32(a.SourceID),                     // int32
		strconv.FormatBool(a.IsTemplate),            // bool
		formatInt32(int32(len(a.FlowSets))),         // []*NetFlowV9FlowSet
		a.SrcIP,
		a.DstIP,
	})
}

// Time returns the timestamp associated with the audit record.
func (a *NetFlowV9) Time() int64 {
	return a.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (a *NetFlowV9) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	a.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(a)
}

var netflowV9Metric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_NetFlowV9.String()),
		Help: Type_NC_NetFlowV9.String() + " audit records",
	},
	fieldsNetFlowV9[1:],
)

// Inc increments the metrics for the audit record.
func (a *NetFlowV9) Inc() {
	netflowV9Metric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (a *NetFlowV9) SetPacketContext(ctx *PacketContext) {
	a.SrcIP = ctx.SrcIP
	a.DstIP = ctx.DstIP
}

// Src returns the source address of the audit record.
func (a *NetFlowV9) Src() string {
	return a.SrcIP
}

// Dst returns the destination address of the audit record.
func (a *NetFlowV9) Dst() string {
	return a.DstIP
}

var netflowV9Encoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (a *NetFlowV9) Encode() []string {
	return filter([]string{
		netflowV9Encoder.Int64(fieldTimestamp, a.Timestamp),
		netflowV9Encoder.Int32(fieldVersion, a.Version),                      // int32
		netflowV9Encoder.Int32(fieldCount, a.Count),                          // int32
		netflowV9Encoder.Int64(fieldSysUptime, a.SysUptime),                  // int64
		netflowV9Encoder.Int64(fieldUnixSecs, a.UnixSecs),                    // int64
		netflowV9Encoder.Int32(fieldSequenceNumber, a.SequenceNumber),        // int32
		netflowV9Encoder.Int32(fieldSourceID, a.SourceID),                    // int32
		netflowV9Encoder.Bool(a.IsTemplate),                                  // bool
		netflowV9Encoder.Int32(fieldFlowSets, int32(len(a.FlowSets))),        // []*NetFlowV9FlowSet
		netflowV9Encoder.String(fieldSrcIP, a.SrcIP),
		netflowV9Encoder.String(fieldDstIP, a.DstIP),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (a *NetFlowV9) Analyze() {
}

// NetcapType returns the type of the current audit record
func (a *NetFlowV9) NetcapType() Type {
	return Type_NC_NetFlowV9
}
