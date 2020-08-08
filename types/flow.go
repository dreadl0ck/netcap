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
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

var fieldsFlow = []string{
	"TimestampFirst",
	"LinkProto",
	"NetworkProto",
	"TransportProto",
	"ApplicationProto",
	"SrcMAC",
	"DstMAC",
	"SrcIP",
	"SrcPort",
	"DstIP",
	"DstPort",
	"TotalSize",
	"AppPayloadSize",
	"NumPackets",
	"UID",
	"Duration",
	"TimestampLast",
}

// CSVHeader returns the CSV header for the audit record.
func (f *Flow) CSVHeader() []string {
	return filter(fieldsFlow)
}

// CSVRecord returns the CSV record for the audit record.
func (f *Flow) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(f.TimestampFirst),
		f.LinkProto,
		f.NetworkProto,
		f.TransportProto,
		f.ApplicationProto,
		f.SrcMAC,
		f.DstMAC,
		f.SrcIP,
		f.SrcPort,
		f.DstIP,
		f.DstPort,
		formatInt32(f.TotalSize),
		formatInt32(f.AppPayloadSize),
		formatInt32(f.NumPackets),
		f.UID,
		formatInt64(f.Duration),
		formatTimestamp(f.TimestampLast),
	})
}

// Time returns the timestamp associated with the audit record.
func (f *Flow) Time() string {
	return f.TimestampFirst
}

// JSON returns the JSON representation of the audit record.
func (f *Flow) JSON() (string, error) {
	return jsonMarshaler.MarshalToString(f)
}

var (
	flowMetric = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: strings.ToLower(Type_NC_Flow.String()),
			Help: Type_NC_Flow.String() + " audit records",
		},
		fieldsFlowMetrics,
	)
	flowTotalSize = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    strings.ToLower(Type_NC_Flow.String()) + "_size",
			Help:    Type_NC_Flow.String() + " payload entropy",
			Buckets: prometheus.LinearBuckets(20, 5, 5),
		},
		[]string{"SrcMAC", "DstMAC"},
	)
	flowAppPayloadSize = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    strings.ToLower(Type_NC_Flow.String()) + "_payload_size",
			Help:    Type_NC_Flow.String() + " payload sizes",
			Buckets: prometheus.LinearBuckets(20, 5, 5),
		},
		[]string{"SrcMAC", "DstMAC"},
	)
	flowNumPackets = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    strings.ToLower(Type_NC_Flow.String()) + "_numpackets",
			Help:    Type_NC_Flow.String() + " payload sizes",
			Buckets: prometheus.LinearBuckets(20, 5, 5),
		},
		[]string{"SrcMAC", "DstMAC"},
	)
	flowDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    strings.ToLower(Type_NC_Flow.String()) + "_duration",
			Help:    Type_NC_Flow.String() + " payload sizes",
			Buckets: prometheus.LinearBuckets(20, 5, 5),
		},
		[]string{"SrcMAC", "DstMAC"},
	)
)

var fieldsFlowMetrics = []string{
	"LinkProto",
	"NetworkProto",
	"TransportProto",
	"ApplicationProto",
	"SrcMAC",
	"DstMAC",
	"SrcIP",
	"SrcPort",
	"DstIP",
	"DstPort",
}

func (f *Flow) metricValues() []string {
	return []string{
		f.LinkProto,
		f.NetworkProto,
		f.TransportProto,
		f.ApplicationProto,
		f.SrcMAC,
		f.DstMAC,
		f.SrcIP,
		f.SrcPort,
		f.DstIP,
		f.DstPort,
	}
}

// Inc increments the metrics for the audit record.
func (f *Flow) Inc() {
	flowMetric.WithLabelValues(f.metricValues()...).Inc()
	flowTotalSize.WithLabelValues(f.SrcMAC, f.DstMAC).Observe(float64(f.TotalSize))
	flowAppPayloadSize.WithLabelValues(f.SrcMAC, f.DstMAC).Observe(float64(f.AppPayloadSize))
	flowNumPackets.WithLabelValues(f.SrcMAC, f.DstMAC).Observe(float64(f.NumPackets))
	flowDuration.WithLabelValues(f.SrcMAC, f.DstMAC).Observe(float64(f.Duration))
}

// SetPacketContext sets the associated packet context for the audit record.
func (f *Flow) SetPacketContext(*PacketContext) {}

// Src returns the source address of the audit record.
func (f *Flow) Src() string {
	return f.SrcIP
}

// Dst returns the destination address of the audit record.
func (f *Flow) Dst() string {
	return f.DstIP
}
