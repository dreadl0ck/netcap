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
	fieldLeapIndicator      = "LeapIndicator"
	fieldMode               = "Mode"
	fieldStratum            = "Stratum"
	fieldPrecision          = "Precision"
	fieldRootDelay          = "RootDelay"
	fieldRootDispersion     = "RootDispersion"
	fieldReferenceID        = "ReferenceID"
	fieldReferenceTimestamp = "ReferenceTimestamp"
	fieldOriginTimestamp    = "OriginTimestamp"
	fieldReceiveTimestamp   = "ReceiveTimestamp"
	fieldTransmitTimestamp  = "TransmitTimestamp"
	fieldExtensionBytes     = "ExtensionBytes"
)

var fieldsNTP = []string{
	fieldTimestamp,
	fieldLeapIndicator,
	fieldVersion,
	fieldMode,
	fieldStratum,
	fieldPoll,
	fieldPrecision,
	fieldRootDelay,
	fieldRootDispersion,
	fieldReferenceID,
	fieldReferenceTimestamp,
	fieldOriginTimestamp,
	fieldReceiveTimestamp,
	fieldTransmitTimestamp,
	fieldExtensionBytes,
	fieldSrcIP,
	fieldDstIP,
	fieldSrcPort,
	fieldDstPort,
}

// CSVHeader returns the CSV header for the audit record.
func (n *NTP) CSVHeader() []string {
	return filter(fieldsNTP)
}

// CSVRecord returns the CSV record for the audit record.
func (n *NTP) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(n.Timestamp),
		formatInt32(n.LeapIndicator),                     // int32
		formatInt32(n.Version),                           // int32
		formatInt32(n.Mode),                              // int32
		formatInt32(n.Stratum),                           // int32
		formatInt32(n.Poll),                              // int32
		formatInt32(n.Precision),                         // int32
		strconv.FormatUint(uint64(n.RootDelay), 10),      // uint32
		strconv.FormatUint(uint64(n.RootDispersion), 10), // uint32
		strconv.FormatUint(uint64(n.ReferenceID), 10),    // uint32
		strconv.FormatUint(n.ReferenceTimestamp, 10),     // uint64
		strconv.FormatUint(n.OriginTimestamp, 10),        // uint64
		strconv.FormatUint(n.ReceiveTimestamp, 10),       // uint64
		strconv.FormatUint(n.TransmitTimestamp, 10),      // uint64
		hex.EncodeToString(n.ExtensionBytes),             // []byte
		n.SrcIP,
		n.DstIP,
		formatInt32(n.SrcPort),
		formatInt32(n.DstPort),
	})
}

// Time returns the timestamp associated with the audit record.
func (n *NTP) Time() int64 {
	return n.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (n *NTP) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	n.Timestamp /= int64(time.Millisecond)
	n.ReferenceTimestamp /= uint64(time.Millisecond)

	return jsonMarshaler.MarshalToString(n)
}

var ntpMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_NTP.String()),
		Help: Type_NC_NTP.String() + " audit records",
	},
	fieldsNTP[1:],
)

// Inc increments the metrics for the audit record.
func (n *NTP) Inc() {
	ntpMetric.WithLabelValues(n.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (n *NTP) SetPacketContext(ctx *PacketContext) {
	n.SrcIP = ctx.SrcIP
	n.DstIP = ctx.DstIP
	n.SrcPort = ctx.SrcPort
	n.DstPort = ctx.DstPort
}

// Src returns the source address of the audit record.
func (n *NTP) Src() string {
	return n.SrcIP
}

// Dst returns the destination address of the audit record.
func (n *NTP) Dst() string {
	return n.DstIP
}

var ntpEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (n *NTP) Encode() []string {
	return filter([]string{
		ntpEncoder.Int64(fieldTimestamp, n.Timestamp),
		ntpEncoder.Int32(fieldLeapIndicator, n.LeapIndicator),                        // int32
		ntpEncoder.Int32(fieldVersion, n.Version),                                    // int32
		ntpEncoder.Int32(fieldMode, n.Mode),                                          // int32
		ntpEncoder.Int32(fieldStratum, n.Stratum),                                    // int32
		ntpEncoder.Int32(fieldPoll, n.Poll),                                          // int32
		ntpEncoder.Int32(fieldPrecision, n.Precision),                                // int32
		ntpEncoder.Uint32(fieldRootDelay, n.RootDelay),                               // uint32
		ntpEncoder.Uint32(fieldRootDispersion, n.RootDispersion),                     // uint32
		ntpEncoder.Uint32(fieldReferenceID, n.ReferenceID),                           // uint32
		ntpEncoder.Uint64(fieldReferenceTimestamp, n.ReferenceTimestamp),             // uint64
		ntpEncoder.Uint64(fieldOriginTimestamp, n.OriginTimestamp),                   // uint64
		ntpEncoder.Uint64(fieldReceiveTimestamp, n.ReceiveTimestamp),                 // uint64
		ntpEncoder.Uint64(fieldTransmitTimestamp, n.TransmitTimestamp),               // uint64
		ntpEncoder.String(fieldExtensionBytes, hex.EncodeToString(n.ExtensionBytes)), // []byte
		ntpEncoder.String(fieldSrcIP, n.SrcIP),
		ntpEncoder.String(fieldDstIP, n.DstIP),
		ntpEncoder.Int32(fieldSrcPort, n.SrcPort),
		ntpEncoder.Int32(fieldDstPort, n.DstPort),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (n *NTP) Analyze() {}

// NetcapType returns the type of the current audit record
func (n *NTP) NetcapType() Type {
	return Type_NC_NTP
}
