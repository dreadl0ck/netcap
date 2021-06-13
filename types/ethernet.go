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
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	fieldTimestamp      = "Timestamp"
	fieldSrcMAC         = "SrcMAC"
	fieldDstMAC         = "DstMAC"
	fieldEthernetType   = "EthernetType"
	fieldPayloadEntropy = "PayloadEntropy"
	fieldPayloadSize    = "PayloadSize"
)

var fieldsEthernet = []string{
	fieldTimestamp,
	fieldSrcMAC,         // string
	fieldDstMAC,         // string
	fieldEthernetType,   // int32
	fieldPayloadEntropy, // float64
	fieldPayloadSize,    // int32
}

// CSVHeader returns the CSV header for the audit record.
func (eth *Ethernet) CSVHeader() []string {
	return filter(fieldsEthernet)
}

// CSVRecord returns the CSV record for the audit record.
func (eth *Ethernet) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(eth.Timestamp),
		eth.SrcMAC,                        // string
		eth.DstMAC,                        // string
		formatInt32(eth.EthernetType),     // int32
		formatFloat64(eth.PayloadEntropy), // float64
		formatInt32(eth.PayloadSize),      // int32
	})
}

// Time returns the timestamp associated with the audit record.
func (eth *Ethernet) Time() int64 {
	return eth.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (eth *Ethernet) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	eth.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(eth)
}

var (
	ethernetMetric = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: strings.ToLower(Type_NC_Ethernet.String()),
			Help: Type_NC_Ethernet.String() + " audit records",
		},
		fieldsEthernetMetrics,
	)
	ethernetPayloadEntropy = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    strings.ToLower(Type_NC_Ethernet.String()) + "_entropy",
			Help:    Type_NC_Ethernet.String() + " payload entropy",
			Buckets: prometheus.LinearBuckets(20, 5, 5),
		},
		// fieldsEthernetMetrics,
		[]string{},
	)
	ethernetPayloadSize = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    strings.ToLower(Type_NC_Ethernet.String()) + "_size",
			Help:    Type_NC_Ethernet.String() + " payload sizes",
			Buckets: prometheus.LinearBuckets(20, 5, 5),
		},
		// fieldsEthernetMetrics,
		[]string{},
	)
)

var fieldsEthernetMetrics = []string{
	fieldSrcMAC,       // string
	fieldDstMAC,       // string
	fieldEthernetType, // int32
}

func (eth *Ethernet) metricValues() []string {
	return []string{
		eth.SrcMAC,                    // string
		eth.DstMAC,                    // string
		formatInt32(eth.EthernetType), // int32
	}
}

// Inc increments the metrics for the audit record.
func (eth *Ethernet) Inc() {
	ethernetMetric.WithLabelValues(eth.metricValues()...).Inc()
	ethernetPayloadEntropy.WithLabelValues().Observe(eth.PayloadEntropy)
	ethernetPayloadSize.WithLabelValues().Observe(float64(eth.PayloadSize))
}

// SetPacketContext sets the associated packet context for the audit record.
func (eth *Ethernet) SetPacketContext(*PacketContext) {}

// Src returns the source address of the audit record.
func (eth *Ethernet) Src() string {
	return eth.SrcMAC
}

// Dst returns the destination address of the audit record.
func (eth *Ethernet) Dst() string {
	return eth.DstMAC
}

var ethernetEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (eth *Ethernet) Encode() []string {
	return filter([]string{
		ethernetEncoder.Int64(fieldTimestamp, eth.Timestamp),
		ethernetEncoder.String(fieldSrcMAC, eth.SrcMAC),
		ethernetEncoder.String(fieldDstMAC, eth.DstMAC),
		ethernetEncoder.Int32(fieldEthernetType, eth.EthernetType),
		ethernetEncoder.Float64(fieldPayloadEntropy, eth.PayloadEntropy),
		ethernetEncoder.Int32(fieldPayloadSize, eth.PayloadSize),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (eth *Ethernet) Analyze() {}

// NetcapType returns the type of the current audit record
func (eth *Ethernet) NetcapType() Type {
	return Type_NC_Ethernet
}
