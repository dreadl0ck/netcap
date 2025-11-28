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
	fieldValidIDFlag      = "ValidIDFlag"
	fieldGBPExtension     = "GBPExtension"
	fieldGBPDontLearn     = "GBPDontLearn"
	fieldGBPApplied       = "GBPApplied"
	fieldGBPGroupPolicyID = "GBPGroupPolicyID"
)

var fieldsVXLAN = []string{
	fieldTimestamp,
	fieldValidIDFlag,      //  bool
	fieldVNI,              //  uint32
	fieldGBPExtension,     //  bool
	fieldGBPDontLearn,     //  bool
	fieldGBPApplied,       //  bool
	fieldGBPGroupPolicyID, //  int32
}

// CSVHeader returns the CSV header for the audit record.
func (a *VXLAN) CSVHeader() []string {
	return filter(fieldsVXLAN)
}

// CSVRecord returns the CSV record for the audit record.
func (a *VXLAN) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(a.Timestamp),
		strconv.FormatBool(a.ValidIDFlag),  //  bool
		formatUint32(a.VNI),                //  uint32
		strconv.FormatBool(a.GBPExtension), //  bool
		strconv.FormatBool(a.GBPDontLearn), //  bool
		strconv.FormatBool(a.GBPApplied),   //  bool
		formatInt32(a.GBPGroupPolicyID),    //  int32
	})
}

// Time returns the timestamp associated with the audit record.
func (a *VXLAN) Time() int64 {
	return a.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (a *VXLAN) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	a.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(a)
}

var vxlanMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_VXLAN.String()),
		Help: Type_NC_VXLAN.String() + " audit records",
	},
	fieldsVXLAN[1:],
)

// Inc increments the metrics for the audit record.
func (a *VXLAN) Inc() {
	vxlanMetric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (a *VXLAN) SetPacketContext(_ *PacketContext) {
}

// Src returns the source address of the audit record.
func (a *VXLAN) Src() string {
	return ""
}

// Dst returns the destination address of the audit record.
func (a *VXLAN) Dst() string {
	return ""
}

var vxlanEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (a *VXLAN) Encode() []string {
	return filter([]string{
		vxlanEncoder.Int64(fieldTimestamp, a.Timestamp),
		vxlanEncoder.Bool(a.ValidIDFlag),                              //  bool
		vxlanEncoder.Uint32(fieldVNI, a.VNI),                          //  uint32
		vxlanEncoder.Bool(a.GBPExtension),                             //  bool
		vxlanEncoder.Bool(a.GBPDontLearn),                             //  bool
		vxlanEncoder.Bool(a.GBPApplied),                               //  bool
		vxlanEncoder.Int32(fieldGBPGroupPolicyID, a.GBPGroupPolicyID), //  int32
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (a *VXLAN) Analyze() {
}

// NetcapType returns the type of the current audit record
func (a *VXLAN) NetcapType() Type {
	return Type_NC_VXLAN
}
