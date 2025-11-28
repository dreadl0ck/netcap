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
	fieldVirtualRtrID = "VirtualRtrID"
	fieldCountIPAddr  = "CountIPAddr"
	fieldAuthType     = "AuthType"
	fieldAdverInt     = "AdverInt"
	fieldIPAddresses  = "IPAddresses"
)

var fieldsVRRPv2 = []string{
	fieldTimestamp,
	fieldVersion,      // int32
	fieldType,         // int32
	fieldVirtualRtrID, // int32
	fieldPriority,     // int32
	fieldCountIPAddr,  // int32
	fieldAuthType,     // int32
	fieldAdverInt,     // int32
	fieldChecksum,     // int32
	fieldIPAddresses,  // []string
	fieldSrcIP,
	fieldDstIP,
}

// CSVHeader returns the CSV header for the audit record.
func (a *VRRPv2) CSVHeader() []string {
	return filter(fieldsVRRPv2)
}

// CSVRecord returns the CSV record for the audit record.
func (a *VRRPv2) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(a.Timestamp),
		formatInt32(a.Version),      // int32
		formatInt32(a.Type),         // int32
		formatInt32(a.VirtualRtrID), // int32
		formatInt32(a.Priority),     // int32
		formatInt32(a.CountIPAddr),  // int32
		formatInt32(a.AuthType),     // int32
		formatInt32(a.AdverInt),     // int32
		formatInt32(a.Checksum),     // int32
		join(a.IPAddress...),        // []string
		a.SrcIP,
		a.DstIP,
	})
}

// Time returns the timestamp associated with the audit record.
func (a *VRRPv2) Time() int64 {
	return a.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (a *VRRPv2) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	a.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(a)
}

var vrrp2Metric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_VRRPv2.String()),
		Help: Type_NC_VRRPv2.String() + " audit records",
	},
	fieldsVRRPv2[1:],
)

// Inc increments the metrics for the audit record.
func (a *VRRPv2) Inc() {
	vrrp2Metric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (a *VRRPv2) SetPacketContext(ctx *PacketContext) {
	a.SrcIP = ctx.SrcIP
	a.DstIP = ctx.DstIP
}

// Src returns the source address of the audit record.
func (a *VRRPv2) Src() string {
	return a.SrcIP
}

// Dst returns the destination address of the audit record.
func (a *VRRPv2) Dst() string {
	return a.DstIP
}

var vrrpv2Encoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (a *VRRPv2) Encode() []string {
	return filter([]string{
		vrrpv2Encoder.Int64(fieldTimestamp, a.Timestamp),
		vrrpv2Encoder.Int32(fieldVersion, a.Version),                 // int32
		vrrpv2Encoder.Int32(fieldType, a.Type),                       // int32
		vrrpv2Encoder.Int32(fieldVirtualRtrID, a.VirtualRtrID),       // int32
		vrrpv2Encoder.Int32(fieldPriority, a.Priority),               // int32
		vrrpv2Encoder.Int32(fieldCountIPAddr, a.CountIPAddr),         // int32
		vrrpv2Encoder.Int32(fieldAuthType, a.AuthType),               // int32
		vrrpv2Encoder.Int32(fieldAdverInt, a.AdverInt),               // int32
		vrrpv2Encoder.Int32(fieldChecksum, a.Checksum),               // int32
		vrrpv2Encoder.String(fieldIPAddresses, join(a.IPAddress...)), // []string
		vrrpv2Encoder.String(fieldSrcIP, a.SrcIP),
		vrrpv2Encoder.String(fieldDstIP, a.DstIP),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (a *VRRPv2) Analyze() {
}

// NetcapType returns the type of the current audit record
func (a *VRRPv2) NetcapType() Type {
	return Type_NC_VRRPv2
}
