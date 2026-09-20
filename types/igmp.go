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
	fieldMaxResponseTime         = "MaxResponseTime"
	fieldGroupAddress            = "GroupAddress"
	fieldSupressRouterProcessing = "SupressRouterProcessing"
	fieldRobustnessValue         = "RobustnessValue"
	fieldIntervalTime            = "IntervalTime"
	fieldSourceAddresses         = "SourceAddresses"
	fieldNumberOfGroupRecords    = "NumberOfGroupRecords"
	fieldNumberOfSources         = "NumberOfSources"
	fieldGroupRecords            = "GroupRecords"
)

var fieldsIGMP = []string{
	fieldTimestamp,
	fieldType,                    // int32
	fieldMaxResponseTime,         // uint64
	fieldChecksum,                // int32
	fieldGroupAddress,            // []byte
	fieldSupressRouterProcessing, // bool
	fieldRobustnessValue,         // int32
	fieldIntervalTime,            // uint64
	fieldSourceAddresses,         // []string
	fieldNumberOfGroupRecords,    // int32
	fieldNumberOfSources,         // int32
	fieldGroupRecords,            // []*IGMPv3GroupRecord
	fieldVersion,                 // int32
	fieldSrcIP,
	fieldDstIP,
}

// CSVHeader returns the CSV header for the audit record.
func (i *IGMP) CSVHeader() []string {
	return filter(fieldsIGMP)
}

// CSVRecord returns the CSV record for the audit record.
func (i *IGMP) CSVRecord() []string {
	records := make([]string, 0, len(i.GroupRecords))
	for _, r := range i.GroupRecords {
		records = append(records, r.toString())
	}

	return filter([]string{
		formatTimestamp(i.Timestamp),
		formatInt32(i.Type),                           // int32
		formatUint64(i.MaxResponseTime),               // uint64
		formatInt32(i.Checksum),                       // int32
		i.GroupAddress,                                // string
		strconv.FormatBool(i.SupressRouterProcessing), // bool
		formatInt32(i.RobustnessValue),                // int32
		formatUint64(i.IntervalTime),                  // uint64
		join(i.SourceAddresses...),                    // []string
		formatInt32(i.NumberOfGroupRecords),           // int32
		formatInt32(i.NumberOfSources),                // int32
		strings.Join(records, ""),                     // []*IGMPv3GroupRecord
		formatInt32(i.Version),                        // int32
		i.SrcIP,
		i.DstIP,
	})
}

// Time returns the timestamp associated with the audit record.
func (i *IGMP) Time() int64 {
	return i.Timestamp
}

func (i *IGMPv3GroupRecord) toString() string {
	if i == nil {
		return ""
	}

	var b strings.Builder
	b.WriteString(StructureBegin)
	b.WriteString(formatInt32(i.Type))
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(i.AuxDataLen))
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(i.NumberOfSources))
	b.WriteString(FieldSeparator)
	b.WriteString(i.MulticastAddress)
	b.WriteString(FieldSeparator)
	b.WriteString(join(i.SourceAddresses...))
	b.WriteString(StructureEnd)

	return b.String()
}

// JSON returns the JSON representation of the audit record.
func (i *IGMP) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	i.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(i)
}

var igmpMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_IGMP.String()),
		Help: Type_NC_IGMP.String() + " audit records",
	},
	fieldsIGMP[1:],
)

// Inc increments the metrics for the audit record.
func (i *IGMP) Inc() {
	igmpMetric.WithLabelValues(i.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (i *IGMP) SetPacketContext(ctx *PacketContext) {
	i.SrcIP = ctx.SrcIP
	i.DstIP = ctx.DstIP
}

// Src returns the source address of the audit record.
func (i *IGMP) Src() string {
	return i.SrcIP
}

// Dst returns the destination address of the audit record.
func (i *IGMP) Dst() string {
	return i.DstIP
}

var igmpEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (i *IGMP) Encode() []string {
	records := make([]string, 0, len(i.GroupRecords))
	for _, r := range i.GroupRecords {
		records = append(records, r.toString())
	}
	return filter([]string{
		igmpEncoder.Int64(fieldTimestamp, i.Timestamp),
		igmpEncoder.Int32(fieldType, i.Type),                                 // int32
		igmpEncoder.Uint64(fieldMaxResponseTime, i.MaxResponseTime),          // uint64
		igmpEncoder.Int32(fieldChecksum, i.Checksum),                         // int32
		igmpEncoder.String(fieldGroupAddress, i.GroupAddress),                // string
		igmpEncoder.Bool(i.SupressRouterProcessing),                          // bool
		igmpEncoder.Int32(fieldRobustnessValue, i.RobustnessValue),           // int32
		igmpEncoder.Uint64(fieldIntervalTime, i.IntervalTime),                // uint64
		igmpEncoder.String(fieldSourceAddresses, join(i.SourceAddresses...)), // []string
		igmpEncoder.Int32(fieldNumberOfGroupRecords, i.NumberOfGroupRecords), // int32
		igmpEncoder.Int32(fieldNumberOfSources, i.NumberOfSources),           // int32
		igmpEncoder.String(fieldGroupRecords, strings.Join(records, "")),     // []*IGMPv3GroupRecord
		igmpEncoder.Int32(fieldVersion, i.Version),                           // int32
		igmpEncoder.String(fieldSrcIP, i.SrcIP),
		igmpEncoder.String(fieldDstIP, i.DstIP),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (i *IGMP) Analyze() {}

// NetcapType returns the type of the current audit record
func (i *IGMP) NetcapType() Type {
	return Type_NC_IGMP
}
