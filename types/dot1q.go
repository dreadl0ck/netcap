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
	fieldPriority       = "Priority"
	fieldDropEligible   = "DropEligible"
	fieldVLANIdentifier = "VLANIdentifier"
	fieldType           = "Type"
)

var fieldsDot1Q = []string{
	fieldTimestamp,
	fieldPriority,       //  int32
	fieldDropEligible,   //  bool
	fieldVLANIdentifier, //  int32
	fieldType,           //  int32
}

// CSVHeader returns the CSV header for the audit record.
func (d *Dot1Q) CSVHeader() []string {
	return filter(fieldsDot1Q)
}

// CSVRecord returns the CSV record for the audit record.
func (d *Dot1Q) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(d.Timestamp),
		formatInt32(d.Priority),            //  int32
		strconv.FormatBool(d.DropEligible), //  bool
		formatInt32(d.VLANIdentifier),      //  int32
		formatInt32(d.Type),                //  int32
	})
}

// Time returns the timestamp associated with the audit record.
func (d *Dot1Q) Time() int64 {
	return d.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (d *Dot1Q) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	d.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(d)
}

var dot1qMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_Dot1Q.String()),
		Help: Type_NC_Dot1Q.String() + " audit records",
	},
	fieldsDot1Q[1:],
)

// Inc increments the metrics for the audit record.
func (d *Dot1Q) Inc() {
	dot1qMetric.WithLabelValues(d.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (d *Dot1Q) SetPacketContext(*PacketContext) {}

// Src TODO: return Mac addr.
// Src returns the source address of the audit record.
func (d *Dot1Q) Src() string {
	return ""
}

// Dst returns the destination address of the audit record.
func (d *Dot1Q) Dst() string {
	return ""
}

var dot1qEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (d *Dot1Q) Encode() []string {
	return filter([]string{
		dot1qEncoder.Int64(fieldTimestamp, d.Timestamp),
		dot1qEncoder.Int32(fieldPriority, d.Priority),             //  int32
		dot1qEncoder.Bool(d.DropEligible),                         //  bool
		dot1qEncoder.Int32(fieldVLANIdentifier, d.VLANIdentifier), //  int32
		dot1qEncoder.Int32(fieldType, d.Type),                     //  int32
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (d *Dot1Q) Analyze() {
}

// NetcapType returns the type of the current audit record
func (d *Dot1Q) NetcapType() Type {
	return Type_NC_Dot1Q
}
