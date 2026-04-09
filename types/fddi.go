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
	fieldFrameControl = "FrameControl"
)

var fieldsFDDI = []string{
	fieldTimestamp,
	fieldFrameControl, //  int32
	fieldPriority,     //  int32
	fieldSrcMAC,       //  string
	fieldDstMAC,       //  string
}

// CSVHeader returns the CSV header for the audit record.
func (a *FDDI) CSVHeader() []string {
	return filter(fieldsFDDI)
}

// CSVRecord returns the CSV record for the audit record.
func (a *FDDI) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(a.Timestamp),
		formatInt32(a.FrameControl), //  int32
		formatInt32(a.Priority),     //  int32
		a.SrcMAC,                    //  string
		a.DstMAC,                    //  string
	})
}

// Time returns the timestamp associated with the audit record.
func (a *FDDI) Time() int64 {
	return a.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (a *FDDI) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	a.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(a)
}

var fddiMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_FDDI.String()),
		Help: Type_NC_FDDI.String() + " audit records",
	},
	fieldsFDDI[1:],
)

// Inc increments the metrics for the audit record.
func (a *FDDI) Inc() {
	fddiMetric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (a *FDDI) SetPacketContext(*PacketContext) {}

// Src returns the source address of the audit record.
func (a *FDDI) Src() string {
	return a.SrcMAC
}

// Dst returns the destination address of the audit record.
func (a *FDDI) Dst() string {
	return a.DstMAC
}

var fddiEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (a *FDDI) Encode() []string {
	return filter([]string{
		fddiEncoder.Int64(fieldTimestamp, a.Timestamp),
		fddiEncoder.Int32(fieldFrameControl, a.FrameControl), //  int32
		fddiEncoder.Int32(fieldPriority, a.Priority),         //  int32
		fddiEncoder.String(fieldSrcMAC, a.SrcMAC),            //  string
		fddiEncoder.String(fieldDstMAC, a.DstMAC),            //  string
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (a *FDDI) Analyze() {}

// NetcapType returns the type of the current audit record
func (a *FDDI) NetcapType() Type {
	return Type_NC_FDDI
}
