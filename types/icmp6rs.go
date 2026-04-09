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
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/encoder"

	"github.com/prometheus/client_golang/prometheus"
)

var fieldsICMPv6RouterSolicitation = []string{
	fieldTimestamp,
	fieldOptions,
	fieldSrcIP,
	fieldDstIP,
}

// CSVHeader returns the CSV header for the audit record.
func (i *ICMPv6RouterSolicitation) CSVHeader() []string {
	return filter(fieldsICMPv6RouterSolicitation)
}

// CSVRecord returns the CSV record for the audit record.
func (i *ICMPv6RouterSolicitation) CSVRecord() []string {
	opts := make([]string, 0, len(i.Options))
	for _, o := range i.Options {
		opts = append(opts, o.toString())
	}

	return filter([]string{
		formatTimestamp(i.Timestamp),
		strings.Join(opts, ""),
		i.SrcIP,
		i.DstIP,
	})
}

// Time returns the timestamp associated with the audit record.
func (i *ICMPv6RouterSolicitation) Time() int64 {
	return i.Timestamp
}

func (o ICMPv6Option) toString() string {
	var b strings.Builder
	b.WriteString(StructureBegin)
	b.WriteString(formatInt32(o.Type))
	b.WriteString(FieldSeparator)
	b.WriteString(hex.EncodeToString(o.Data))
	b.WriteString(StructureEnd)

	return b.String()
}

// JSON returns the JSON representation of the audit record.
func (i *ICMPv6RouterSolicitation) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	i.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(i)
}

var icmp6rsMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_ICMPv6RouterSolicitation.String()),
		Help: Type_NC_ICMPv6RouterSolicitation.String() + " audit records",
	},
	fieldsICMPv6RouterSolicitation[1:],
)

// Inc increments the metrics for the audit record.
func (i *ICMPv6RouterSolicitation) Inc() {
	icmp6rsMetric.WithLabelValues(i.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (i *ICMPv6RouterSolicitation) SetPacketContext(ctx *PacketContext) {
	i.SrcIP = ctx.SrcIP
	i.DstIP = ctx.DstIP
}

// Src returns the source address of the audit record.
func (i *ICMPv6RouterSolicitation) Src() string {
	return i.SrcIP
}

// Dst returns the destination address of the audit record.
func (i *ICMPv6RouterSolicitation) Dst() string {
	return i.DstIP
}

var icmp6rsEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (i *ICMPv6RouterSolicitation) Encode() []string {
	opts := make([]string, 0, len(i.Options))
	for _, o := range i.Options {
		opts = append(opts, o.toString())
	}
	return filter([]string{
		icmp6rsEncoder.Int64(fieldTimestamp, i.Timestamp),
		icmp6rsEncoder.String(fieldOptions, strings.Join(opts, "")),
		icmp6rsEncoder.String(fieldSrcIP, i.SrcIP),
		icmp6rsEncoder.String(fieldDstIP, i.DstIP),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (i *ICMPv6RouterSolicitation) Analyze() {}

// NetcapType returns the type of the current audit record
func (i *ICMPv6RouterSolicitation) NetcapType() Type {
	return Type_NC_ICMPv6RouterSolicitation
}
