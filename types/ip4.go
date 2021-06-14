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
	"encoding/hex"
	"strconv"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/encoder"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	fieldIHL        = "IHL"        // int32
	fieldTOS        = "TOS"        // int32
	fieldFragOffset = "FragOffset" // int32
	fieldPadding    = "Padding"    // []byte
)

var fieldsIPv4 = []string{
	fieldTimestamp,
	fieldVersion,    // int32
	fieldIHL,        // int32
	fieldTOS,        // int32
	fieldLength,     // int32
	fieldId,         // int32
	fieldFlags,      // int32
	fieldFragOffset, // int32
	fieldTTL,        // int32
	fieldProtocol,   // int32
	fieldChecksum,   // int32
	fieldSrcIP,      // string
	fieldDstIP,      // string
	//fieldOptions,        // []*IPv4Option
	fieldPayloadEntropy, // float64
	fieldPayloadSize,    // int32
}

// CSVHeader returns the CSV header for the audit record.
func (i *IPv4) CSVHeader() []string {
	return filter(fieldsIPv4)
}

// CSVRecord returns the CSV record for the audit record.
func (i *IPv4) CSVRecord() []string {
	// var opts []string
	// for _, o := range i.Options {
	// 	opts = append(opts, o.toString())
	// }
	return filter([]string{
		formatTimestamp(i.Timestamp),
		formatInt32(i.Version),        // int32
		formatInt32(i.IHL),            // int32
		formatInt32(i.TOS),            // int32
		formatInt32(i.Length),         // int32
		formatInt32(i.Id),             // int32
		formatInt32(i.Flags),          // int32
		formatInt32(i.FragOffset),     // int32
		formatInt32(i.TTL),            // int32
		formatInt32(i.Protocol),       // int32
		formatInt32(i.Checksum),       // int32
		i.SrcIP,                       // string
		i.DstIP,                       // string
		hex.EncodeToString(i.Padding), // []byte
		//strings.Join(opts, ""),        // []*IPv4Option
		strconv.FormatFloat(i.PayloadEntropy, 'f', 6, 64), // float64
		formatInt32(i.PayloadSize),                        // int32
	})
}

// Time returns the timestamp associated with the audit record.
func (i *IPv4) Time() int64 {
	return i.Timestamp
}

func (i IPv4Option) toString() string {
	var b strings.Builder
	b.WriteString(StructureBegin)
	b.WriteString(formatInt32(i.OptionType))
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(i.OptionLength))
	b.WriteString(FieldSeparator)
	b.WriteString(hex.EncodeToString(i.OptionData))
	b.WriteString(StructureEnd)

	return b.String()
}

// JSON returns the JSON representation of the audit record.
func (i *IPv4) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	i.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(i)
}

var (
	ip4Metric = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: strings.ToLower(Type_NC_IPv4.String()),
			Help: Type_NC_IPv4.String() + " audit records",
		},
		fieldsIPv4Metrics,
	)
	ip4PayloadEntropy = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    strings.ToLower(Type_NC_IPv4.String()) + "_entropy",
			Help:    Type_NC_IPv4.String() + " payload entropy",
			Buckets: prometheus.LinearBuckets(20, 5, 5),
		},
		[]string{},
		// []string{"SrcIP", "DstIP"},
	)
	ip4PayloadSize = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    strings.ToLower(Type_NC_IPv4.String()) + "_size",
			Help:    Type_NC_IPv4.String() + " payload sizes",
			Buckets: prometheus.LinearBuckets(20, 5, 5),
		},
		[]string{},
		// []string{"SrcIP", "DstIP"},
	)
)

var fieldsIPv4Metrics = []string{
	fieldVersion, // int32
	fieldIHL,     // int32
	fieldTOS,     // int32
	//fieldLength,  // int32
	//fieldId,         // int32
	fieldFlags,      // int32
	fieldFragOffset, // int32
	fieldTTL,        // int32
	fieldProtocol,   // int32
	fieldSrcIP,      // string
	fieldDstIP,      // string
}

func (i *IPv4) metricValues() []string {
	return []string{
		formatInt32(i.Version), // int32
		formatInt32(i.IHL),     // int32
		formatInt32(i.TOS),     // int32
		// formatInt32(i.Length),  // int32
		// formatInt32(i.Id),         // int32
		formatInt32(i.Flags),      // int32
		formatInt32(i.FragOffset), // int32
		formatInt32(i.TTL),        // int32
		formatInt32(i.Protocol),   // int32
		i.SrcIP,                   // string
		i.DstIP,                   // string
	}
}

// Inc increments the metrics for the audit record.
func (i *IPv4) Inc() {
	ip4Metric.WithLabelValues(i.metricValues()...).Inc()
	ip4PayloadEntropy.WithLabelValues().Observe(i.PayloadEntropy)
	ip4PayloadSize.WithLabelValues().Observe(float64(i.PayloadSize))
}

// SetPacketContext sets the associated packet context for the audit record.
func (i *IPv4) SetPacketContext(ctx *PacketContext) {
	i.SrcPort = ctx.SrcPort
	i.DstPort = ctx.DstPort
}

// Src returns the source address of the audit record.
func (i *IPv4) Src() string {
	return i.SrcIP
}

// Dst returns the destination address of the audit record.
func (i *IPv4) Dst() string {
	return i.DstIP
}

var ipv4Encoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (i *IPv4) Encode() []string {
	// var opts []string
	// for _, o := range i.Options {
	// 	opts = append(opts, o.toString())
	// }
	return filter([]string{
		ipv4Encoder.Int64(fieldTimestamp, i.Timestamp),
		ipv4Encoder.Int32(fieldVersion, i.Version),        // int32
		ipv4Encoder.Int32(fieldIHL, i.IHL),                // int32
		ipv4Encoder.Int32(fieldTOS, i.TOS),                // int32
		ipv4Encoder.Int32(fieldLength, i.Length),          // int32
		ipv4Encoder.Int32(fieldId, i.Id),                  // int32
		ipv4Encoder.Int32(fieldFlags, i.Flags),            // int32
		ipv4Encoder.Int32(fieldFragOffset, i.FragOffset),  // int32
		ipv4Encoder.Int32(fieldTTL, i.TTL),                // int32
		ipv4Encoder.Int32(fieldProtocol, i.Protocol),      // int32
		ipv4Encoder.Int32(fieldChecksum, i.Checksum),      // int32
		ipv4Encoder.Int64(fieldSrcIP, ipToInt64(i.SrcIP)), // string
		ipv4Encoder.Int64(fieldDstIP, ipToInt64(i.DstIP)), // string
		//ipv4Encoder.String(fieldOptions, strings.Join(opts, "")),   // []*IPv4Option
		ipv4Encoder.Float64(fieldPayloadEntropy, i.PayloadEntropy), // float64
		ipv4Encoder.Int32(fieldPayloadSize, i.PayloadSize),         // int32
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (i *IPv4) Analyze() {}

// NetcapType returns the type of the current audit record
func (i *IPv4) NetcapType() Type {
	return Type_NC_IPv4
}
