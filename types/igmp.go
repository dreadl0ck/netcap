/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017-2020 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package types

import (
	"github.com/dreadl0ck/netcap/encoder"
	"strconv"
	"strings"
	"time"

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
	var records []string
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

func (i IGMPv3GroupRecord) toString() string {
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
	var records []string
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
