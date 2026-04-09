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
	fieldRMCPSequence      = "Sequence"
	fieldRMCPAck           = "Ack"
	fieldRMCPClass         = "Class"
	fieldRMCPClassName     = "ClassName"
	fieldRMCPIsIPMI        = "IsIPMI"
	fieldRMCPIsASF         = "IsASF"
	fieldRMCPNoAckRequired = "NoAckRequired"
)

var fieldsRMCP = []string{
	fieldTimestamp,
	fieldVersion,           // int32
	fieldRMCPSequence,      // int32
	fieldRMCPAck,           // bool
	fieldRMCPClass,         // int32
	fieldRMCPClassName,     // string
	fieldSrcIP,             // string
	fieldDstIP,             // string
	fieldSrcPort,           // int32
	fieldDstPort,           // int32
	fieldRMCPIsIPMI,        // bool
	fieldRMCPIsASF,         // bool
	fieldRMCPNoAckRequired, // bool
}

// CSVHeader returns the CSV header for the audit record.
func (r *RMCP) CSVHeader() []string {
	return filter(fieldsRMCP)
}

// CSVRecord returns the CSV record for the audit record.
func (r *RMCP) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(r.Timestamp),
		formatInt32(r.Version),              // int32
		formatInt32(r.Sequence),             // int32
		strconv.FormatBool(r.Ack),           // bool
		formatInt32(r.Class),                // int32
		r.ClassName,                         // string
		r.SrcIP,                             // string
		r.DstIP,                             // string
		formatInt32(r.SrcPort),              // int32
		formatInt32(r.DstPort),              // int32
		strconv.FormatBool(r.IsIPMI),        // bool
		strconv.FormatBool(r.IsASF),         // bool
		strconv.FormatBool(r.NoAckRequired), // bool
	})
}

// Time returns the timestamp associated with the audit record.
func (r *RMCP) Time() int64 {
	return r.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (r *RMCP) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	r.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(r)
}

var rmcpMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_RMCP.String()),
		Help: Type_NC_RMCP.String() + " audit records",
	},
	fieldsRMCP[1:],
)

// Inc increments the metrics for the audit record.
func (r *RMCP) Inc() {
	rmcpMetric.WithLabelValues(r.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (r *RMCP) SetPacketContext(ctx *PacketContext) {
	r.SrcIP = ctx.SrcIP
	r.DstIP = ctx.DstIP
	r.SrcPort = ctx.SrcPort
	r.DstPort = ctx.DstPort
}

// Src returns the source address of the audit record.
func (r *RMCP) Src() string {
	return r.SrcIP
}

// Dst returns the destination address of the audit record.
func (r *RMCP) Dst() string {
	return r.DstIP
}

var rmcpEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (r *RMCP) Encode() []string {
	return filter([]string{
		rmcpEncoder.Int64(fieldTimestamp, r.Timestamp),
		rmcpEncoder.Int32(fieldVersion, r.Version),          // int32
		rmcpEncoder.Int32(fieldRMCPSequence, r.Sequence),    // int32
		rmcpEncoder.Bool(r.Ack),                             // bool
		rmcpEncoder.Int32(fieldRMCPClass, r.Class),          // int32
		rmcpEncoder.String(fieldRMCPClassName, r.ClassName), // string
		rmcpEncoder.String(fieldSrcIP, r.SrcIP),             // string
		rmcpEncoder.String(fieldDstIP, r.DstIP),             // string
		rmcpEncoder.Int32(fieldSrcPort, r.SrcPort),          // int32
		rmcpEncoder.Int32(fieldDstPort, r.DstPort),          // int32
		rmcpEncoder.Bool(r.IsIPMI),                          // bool
		rmcpEncoder.Bool(r.IsASF),                           // bool
		rmcpEncoder.Bool(r.NoAckRequired),                   // bool
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (r *RMCP) Analyze() {}

// NetcapType returns the type of the current audit record
func (r *RMCP) NetcapType() Type {
	return Type_NC_RMCP
}
