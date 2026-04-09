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

var fieldsEAPOL = []string{
	fieldTimestamp,
	fieldVersion, //  int32
	fieldType,    //  int32
	fieldLength,  //  int32
}

// CSVHeader returns the CSV header for the audit record.
func (a *EAPOL) CSVHeader() []string {
	return filter(fieldsEAPOL)
}

// CSVRecord returns the CSV record for the audit record.
func (a *EAPOL) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(a.Timestamp),
		formatInt32(a.Version), //  int32
		formatInt32(a.Type),    //  int32
		formatInt32(a.Length),  //  int32
	})
}

// Time returns the timestamp associated with the audit record.
func (a *EAPOL) Time() int64 {
	return a.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (a *EAPOL) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	a.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(a)
}

var eapPolMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_EAPOL.String()),
		Help: Type_NC_EAPOL.String() + " audit records",
	},
	fieldsEAPOL[1:],
)

// Inc increments the metrics for the audit record.
func (a *EAPOL) Inc() {
	eapPolMetric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (a *EAPOL) SetPacketContext(*PacketContext) {}

// Src TODO: return Mac addr.
// Src returns the source address of the audit record.
func (a *EAPOL) Src() string {
	return ""
}

// Dst returns the destination address of the audit record.
func (a *EAPOL) Dst() string {
	return ""
}

var eapolEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (a *EAPOL) Encode() []string {
	return filter([]string{
		eapolEncoder.Int64(fieldTimestamp, a.Timestamp),
		eapolEncoder.Int32(fieldVersion, a.Version), //  int32
		eapolEncoder.Int32(fieldType, a.Type),       //  int32
		eapolEncoder.Int32(fieldLength, a.Length),   //  int32
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (a *EAPOL) Analyze() {}

// NetcapType returns the type of the current audit record
func (a *EAPOL) NetcapType() Type {
	return Type_NC_EAPOL
}
