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
	fieldTrafficClass = "TrafficClass"
	fieldFlowLabel    = "FlowLabel"
	fieldNextHeader   = "NextHeader"
	fieldHopByHop     = "HopByHop"
)

var fieldsIPv6 = []string{
	fieldTimestamp,
	fieldVersion,        // int32
	fieldTrafficClass,   // int32
	fieldFlowLabel,      // uint32
	fieldLength,         // int32
	fieldNextHeader,     // int32
	fieldHopLimit,       // int32
	fieldSrcIP,          // string
	fieldDstIP,          // string
	fieldPayloadEntropy, // float64
	fieldPayloadSize,    // int32
	//fieldHopByHop,       // *IPv6HopByHop
}

// CSVHeader returns the CSV header for the audit record.
func (i *IPv6) CSVHeader() []string {
	return filter(fieldsIPv6)
}

// CSVRecord returns the CSV record for the audit record.
func (i *IPv6) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(i.Timestamp),
		formatInt32(i.Version),      // int32
		formatInt32(i.TrafficClass), // int32
		formatUint32(i.FlowLabel),   // uint32
		formatInt32(i.Length),       // int32
		formatInt32(i.NextHeader),   // int32
		formatInt32(i.HopLimit),     // int32
		i.SrcIP,                     // string
		i.DstIP,                     // string
		strconv.FormatFloat(i.PayloadEntropy, 'f', 6, 64), // float64
		formatInt32(i.PayloadSize),                        // int32
		//hop,                                               // *IPv6HopByHop
	})
}

// Time returns the timestamp associated with the audit record.
func (i *IPv6) Time() int64 {
	return i.Timestamp
}

func (h IPv6HopByHop) toString() string {
	var opts []string
	for _, o := range h.Options {
		opts = append(opts, o.toString())
	}

	return strconv.FormatInt(h.Timestamp, 10) + FieldSeparator + join(opts...)
}

// JSON returns the JSON representation of the audit record.
func (i *IPv6) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	i.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(i)
}

var (
	ip6Metric = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: strings.ToLower(Type_NC_IPv6.String()),
			Help: Type_NC_IPv6.String() + " audit records",
		},
		fieldsIPv6Metrics,
	)
	ip6PayloadEntropy = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    strings.ToLower(Type_NC_IPv6.String()) + "_entropy",
			Help:    Type_NC_IPv6.String() + " payload entropy",
			Buckets: prometheus.LinearBuckets(20, 5, 5),
		},
		// []string{"SrcIP", "DstIP"},
		[]string{},
	)
	ip6PayloadSize = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    strings.ToLower(Type_NC_IPv6.String()) + "_size",
			Help:    Type_NC_IPv6.String() + " payload sizes",
			Buckets: prometheus.LinearBuckets(20, 5, 5),
		},
		// []string{"SrcIP", "DstIP"},
		[]string{},
	)
)

var fieldsIPv6Metrics = []string{
	"Version",      // int32
	"TrafficClass", // int32
	"FlowLabel",    // uint32
	"NextHeader",   // int32
	"HopLimit",     // int32
	"SrcIP",        // string
	"DstIP",        // string
}

func (i *IPv6) metricValues() []string {
	return []string{
		formatInt32(i.Version),      // int32
		formatInt32(i.TrafficClass), // int32
		formatUint32(i.FlowLabel),   // uint32
		formatInt32(i.NextHeader),   // int32
		formatInt32(i.HopLimit),     // int32
		i.SrcIP,                     // string
		i.DstIP,                     // string
	}
}

// Inc increments the metrics for the audit record.
func (i *IPv6) Inc() {
	ip6Metric.WithLabelValues(i.metricValues()...).Inc()
	ip6PayloadEntropy.WithLabelValues().Observe(i.PayloadEntropy)
	ip6PayloadSize.WithLabelValues().Observe(float64(i.PayloadSize))
}

// SetPacketContext sets the associated packet context for the audit record.
func (i *IPv6) SetPacketContext(ctx *PacketContext) {
	i.SrcPort = ctx.SrcPort
	i.DstPort = ctx.DstPort
}

// Src returns the source address of the audit record.
func (i *IPv6) Src() string {
	return i.SrcIP
}

// Dst returns the destination address of the audit record.
func (i *IPv6) Dst() string {
	return i.DstIP
}

var ipv6Encoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (i *IPv6) Encode() []string {
	return filter([]string{
		ipv6Encoder.Int64(fieldTimestamp, i.Timestamp),
		ipv6Encoder.Int32(fieldVersion, i.Version),                 // int32
		ipv6Encoder.Int32(fieldTrafficClass, i.TrafficClass),       // int32
		ipv6Encoder.Uint32(fieldFlowLabel, i.FlowLabel),            // uint32
		ipv6Encoder.Int32(fieldLength, i.Length),                   // int32
		ipv6Encoder.Int32(fieldNextHeader, i.NextHeader),           // int32
		ipv6Encoder.Int32(fieldHopLimit, i.HopLimit),               // int32
		ipv6Encoder.String(fieldSrcIP, i.SrcIP),                    // string
		ipv6Encoder.String(fieldDstIP, i.DstIP),                    // string
		ipv6Encoder.Float64(fieldPayloadEntropy, i.PayloadEntropy), // float64
		ipv6Encoder.Int32(fieldPayloadSize, i.PayloadSize),         // int32
		// TODO: flatten
		//hop,                                               // *IPv6HopByHop
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (i *IPv6) Analyze() {}

// NetcapType returns the type of the current audit record
func (i *IPv6) NetcapType() Type {
	return Type_NC_IPv6
}
