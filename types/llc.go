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
	fieldDSAP       = "DSAP"
	fieldIG         = "IG"
	fieldSSAP       = "SSAP"
	fieldCR         = "CR"
	fieldLLCControl = "Control"
)

var fieldsLLC = []string{
	fieldTimestamp,  // string
	fieldDSAP,       // int32
	fieldIG,         // bool
	fieldSSAP,       // int32
	fieldCR,         // bool
	fieldLLCControl, // int32
}

// CSVHeader returns the CSV header for the audit record.
func (l *LLC) CSVHeader() []string {
	return filter(fieldsLLC)
}

// CSVRecord returns the CSV record for the audit record.
func (l *LLC) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(l.Timestamp),
		formatInt32(l.DSAP),      // int32
		strconv.FormatBool(l.IG), // bool
		formatInt32(l.SSAP),      // int32
		strconv.FormatBool(l.CR), // bool
		formatInt32(l.Control),   // int32
	})
}

// Time returns the timestamp associated with the audit record.
func (l *LLC) Time() int64 {
	return l.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (l *LLC) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	l.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(l)
}

var llcMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_LLC.String()),
		Help: Type_NC_LLC.String() + " audit records",
	},
	fieldsLLC[1:],
)

// Inc increments the metrics for the audit record.
func (l *LLC) Inc() {
	llcMetric.WithLabelValues(l.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (l *LLC) SetPacketContext(*PacketContext) {}

// Src TODO.
// Src returns the source address of the audit record.
func (l *LLC) Src() string {
	return ""
}

// Dst returns the destination address of the audit record.
func (l *LLC) Dst() string {
	return ""
}

var llcEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (l *LLC) Encode() []string {
	return filter([]string{
		ethernetEncoder.Int64(fieldTimestamp, l.Timestamp),
		llcEncoder.Int32(fieldDSAP, l.DSAP),          // int32
		llcEncoder.Bool(l.IG),                        // bool
		llcEncoder.Int32(fieldSSAP, l.SSAP),          // int32
		llcEncoder.Bool(l.CR),                        // bool
		llcEncoder.Int32(fieldLLCControl, l.Control), // int32
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (l *LLC) Analyze() {}

// NetcapType returns the type of the current audit record
func (l *LLC) NetcapType() Type {
	return Type_NC_LLC
}
