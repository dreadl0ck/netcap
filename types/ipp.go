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
	fieldVersionMajor      = "VersionMajor"
	fieldVersionMinor      = "VersionMinor"
	fieldOperationOrStatus = "OperationOrStatus"
	fieldOperationName     = "OperationName"
	fieldRequestID         = "RequestID"
	fieldPrinterURI        = "PrinterURI"
	fieldJobName           = "JobName"
)

var fieldsIPP = []string{
	fieldTimestamp,
	fieldVersionMajor,     // int32
	fieldVersionMinor,     // int32
	fieldOperationOrStatus, // int32
	fieldOperationName,    // string
	fieldRequestID,        // int32
	fieldAttributes,       // []*IPPAttribute
	fieldPrinterURI,       // string
	fieldJobName,          // string
	fieldFlow,
	fieldSrcIP,
	fieldDstIP,
	fieldSrcPort,
	fieldDstPort,
}

// CSVHeader returns the CSV header for the audit record.
func (a *IPP) CSVHeader() []string {
	return filter(fieldsIPP)
}

// CSVRecord returns the CSV record for the audit record.
func (a *IPP) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(a.Timestamp),
		formatInt32(a.VersionMajor),      // int32
		formatInt32(a.VersionMinor),      // int32
		formatInt32(a.OperationOrStatus), // int32
		a.OperationName,                  // string
		formatInt32(a.RequestID),         // int32
		strconv.Itoa(len(a.Attributes)), // []*IPPAttribute
		a.PrinterURI,                     // string
		a.JobName,                        // string
		a.Flow,
		a.SrcIP,
		a.DstIP,
		formatInt32(a.SrcPort),
		formatInt32(a.DstPort),
	})
}

// Time returns the timestamp associated with the audit record.
func (a *IPP) Time() int64 {
	return a.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (a *IPP) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	a.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(a)
}

var ippMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_IPP.String()),
		Help: Type_NC_IPP.String() + " audit records",
	},
	fieldsIPP[1:],
)

// Inc increments the metrics for the audit record.
func (a *IPP) Inc() {
	ippMetric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (a *IPP) SetPacketContext(*PacketContext) {}

// Src returns the source address of the audit record.
func (a *IPP) Src() string {
	return a.SrcIP
}

// Dst returns the destination address of the audit record.
func (a *IPP) Dst() string {
	return a.DstIP
}

var ippEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (a *IPP) Encode() []string {
	return filter([]string{
		ippEncoder.Int64(fieldTimestamp, a.Timestamp),
		ippEncoder.Int32(fieldVersionMajor, a.VersionMajor),            // int32
		ippEncoder.Int32(fieldVersionMinor, a.VersionMinor),            // int32
		ippEncoder.Int32(fieldOperationOrStatus, a.OperationOrStatus),  // int32
		ippEncoder.String(fieldOperationName, a.OperationName),         // string
		ippEncoder.Int32(fieldRequestID, a.RequestID),                  // int32
		ippEncoder.String(fieldAttributes, strconv.Itoa(len(a.Attributes))), // []*IPPAttribute
		ippEncoder.String(fieldPrinterURI, a.PrinterURI),               // string
		ippEncoder.String(fieldJobName, a.JobName),                     // string
		ippEncoder.String(fieldFlow, a.Flow),
		ippEncoder.String(fieldSrcIP, a.SrcIP),
		ippEncoder.String(fieldDstIP, a.DstIP),
		ippEncoder.Int32(fieldSrcPort, a.SrcPort),
		ippEncoder.Int32(fieldDstPort, a.DstPort),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (a *IPP) Analyze() {
}

// NetcapType returns the type of the current audit record
func (a *IPP) NetcapType() Type {
	return Type_NC_IPP
}
