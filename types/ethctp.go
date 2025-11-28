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

const fieldSkipCount = "SkipCount"

var fieldsEthernetCTP = []string{
	fieldTimestamp,
	fieldSkipCount, // int32
}

// CSVHeader returns the CSV header for the audit record.
func (i *EthernetCTP) CSVHeader() []string {
	return filter(fieldsEthernetCTP)
}

// CSVRecord returns the CSV record for the audit record.
func (i *EthernetCTP) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(i.Timestamp),
		formatInt32(i.SkipCount),
	})
}

// Time returns the timestamp associated with the audit record.
func (i *EthernetCTP) Time() int64 {
	return i.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (i *EthernetCTP) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	i.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(i)
}

var ethernetCTPMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_EthernetCTP.String()),
		Help: Type_NC_EthernetCTP.String() + " audit records",
	},
	fieldsEthernetCTP[1:],
)

// Inc increments the metrics for the audit record.
func (i *EthernetCTP) Inc() {
	ethernetCTPMetric.WithLabelValues(i.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (a *EthernetCTP) SetPacketContext(*PacketContext) {}

// Src TODO.
// Src returns the source address of the audit record.
func (i *EthernetCTP) Src() string {
	return ""
}

// Dst returns the destination address of the audit record.
func (i *EthernetCTP) Dst() string {
	return ""
}

var ethernetCTPEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (i *EthernetCTP) Encode() []string {
	return filter([]string{
		ethernetCTPEncoder.Int64(fieldTimestamp, i.Timestamp),
		ethernetCTPEncoder.Int32(fieldSkipCount, i.SkipCount),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (i *EthernetCTP) Analyze() {}

// NetcapType returns the type of the current audit record
func (a *EthernetCTP) NetcapType() Type {
	return Type_NC_EthernetCTP
}
