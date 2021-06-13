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

var fieldsUDP = []string{
	fieldTimestamp,
	fieldSrcPort,
	fieldDstPort,
	fieldLength, // redundant: PayloadSize + UDP Header Size = Length, remove field from audit record
	fieldChecksum,
	fieldPayloadEntropy,
	fieldPayloadSize,
	//fieldPayload,
	fieldSrcIP,
	fieldDstIP,
}

// CSVHeader returns the CSV header for the audit record.
func (u *UDP) CSVHeader() []string {
	return filter(fieldsUDP)
}

// CSVRecord returns the CSV record for the audit record.
func (u *UDP) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(u.Timestamp),                      // string
		formatInt32(u.SrcPort),                            // int32
		formatInt32(u.DstPort),                            // int32
		formatInt32(u.Length),                             // int32
		formatInt32(u.Checksum),                           // int32
		strconv.FormatFloat(u.PayloadEntropy, 'f', 8, 64), // float64
		formatInt32(u.PayloadSize),                        // int32
		u.SrcIP,
		u.DstIP,
	})
}

// Time returns the timestamp associated with the audit record.
func (u *UDP) Time() int64 {
	return u.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (u *UDP) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	u.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(u)
}

var (
	udpMetric = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: strings.ToLower(Type_NC_UDP.String()),
			Help: Type_NC_UDP.String() + " audit records",
		},
		fieldsUDPMetrics,
	)
	udpPayloadEntropy = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    strings.ToLower(Type_NC_UDP.String()) + "_entropy",
			Help:    Type_NC_UDP.String() + " payload entropy",
			Buckets: prometheus.LinearBuckets(20, 5, 5),
		},
		// fieldsUDPMetrics,
		[]string{},
	)
	udpPayloadSize = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    strings.ToLower(Type_NC_UDP.String()) + "_size",
			Help:    Type_NC_UDP.String() + " payload sizes",
			Buckets: prometheus.LinearBuckets(20, 5, 5),
		},
		// fieldsUDPMetrics,
		[]string{},
	)
)

var fieldsUDPMetrics = []string{
	fieldSrcPort,
	fieldDstPort,
}

func (u *UDP) metricValues() []string {
	return []string{
		formatInt32(u.SrcPort), // int32
		formatInt32(u.DstPort), // int32
	}
}

// Inc increments the metrics for the audit record.
func (u *UDP) Inc() {
	udpMetric.WithLabelValues(u.metricValues()...).Inc()
	udpPayloadEntropy.WithLabelValues().Observe(u.PayloadEntropy)
	udpPayloadSize.WithLabelValues().Observe(float64(u.PayloadSize))
}

// SetPacketContext sets the associated packet context for the audit record.
func (u *UDP) SetPacketContext(ctx *PacketContext) {
	u.SrcIP = ctx.SrcIP
	u.DstIP = ctx.DstIP
}

// Src returns the source address of the audit record.
func (u *UDP) Src() string {
	return u.SrcIP
}

// Dst returns the destination address of the audit record.
func (u *UDP) Dst() string {
	return u.DstIP
}

var udpEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (u *UDP) Encode() []string {
	return filter([]string{
		udpEncoder.Int64(fieldTimestamp, u.Timestamp),             // int64
		udpEncoder.Int32(fieldSrcPort, u.SrcPort),                 // int32
		udpEncoder.Int32(fieldDstPort, u.DstPort),                 // int32
		udpEncoder.Int32(fieldLength, u.Length),                   // int32
		udpEncoder.Int32(fieldChecksum, u.Checksum),               // int32
		udpEncoder.Float64(fieldPayloadEntropy, u.PayloadEntropy), // float64
		udpEncoder.Int32(fieldPayloadSize, u.PayloadSize),         // int32
		udpEncoder.String(fieldSrcIP, u.SrcIP),
		udpEncoder.String(fieldDstIP, u.DstIP),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (u *UDP) Analyze() {

}

// NetcapType returns the type of the current audit record
func (u *UDP) NetcapType() Type {
	return Type_NC_UDP
}
