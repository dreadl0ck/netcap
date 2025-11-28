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

var fieldsICMPv6 = []string{
	fieldTimestamp,
	fieldTypeCode, // int32
	fieldChecksum, // int32
	fieldSrcIP,
	fieldDstIP,
}

// CSVHeader returns the CSV header for the audit record.
func (i *ICMPv6) CSVHeader() []string {
	return filter(fieldsICMPv6)
}

// CSVRecord returns the CSV record for the audit record.
func (i *ICMPv6) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(i.Timestamp),
		formatInt32(i.TypeCode),
		formatInt32(i.Checksum),
		i.SrcIP,
		i.DstIP,
	})
}

// Time returns the timestamp associated with the audit record.
func (i *ICMPv6) Time() int64 {
	return i.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (i *ICMPv6) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	i.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(i)
}

var icmp6Metric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_ICMPv6.String()),
		Help: Type_NC_ICMPv6.String() + " audit records",
	},
	fieldsICMPv6[1:],
)

// Inc increments the metrics for the audit record.
func (i *ICMPv6) Inc() {
	icmp6Metric.WithLabelValues(i.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (i *ICMPv6) SetPacketContext(ctx *PacketContext) {
	i.SrcIP = ctx.SrcIP
	i.DstIP = ctx.DstIP
}

// Src returns the source address of the audit record.
func (i *ICMPv6) Src() string {
	return i.SrcIP
}

// Dst returns the destination address of the audit record.
func (i *ICMPv6) Dst() string {
	return i.DstIP
}

var icmp6Encoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (i *ICMPv6) Encode() []string {
	return filter([]string{
		icmp6Encoder.Int64(fieldTimestamp, i.Timestamp),
		icmp6Encoder.Int32(fieldTypeCode, i.TypeCode),
		icmp6Encoder.Int32(fieldChecksum, i.Checksum),
		icmp6Encoder.String(fieldSrcIP, i.SrcIP),
		icmp6Encoder.String(fieldDstIP, i.DstIP),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (i *ICMPv6) Analyze() {}

// NetcapType returns the type of the current audit record
func (i *ICMPv6) NetcapType() Type {
	return Type_NC_ICMPv6
}
