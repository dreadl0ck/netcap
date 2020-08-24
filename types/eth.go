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

	"github.com/dreadl0ck/netcap/utils"
)

var fieldsEthernet = []string{
	"Timestamp",
	"SrcMAC",         // string
	"DstMAC",         // string
	"EthernetType",   // int32
	"PayloadEntropy", // float64
	"PayloadSize",    // int32
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
func (eth *Ethernet) Time() string {
	return eth.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (eth *Ethernet) JSON() (string, error) {
	eth.Timestamp = utils.TimeToUnixMilli(eth.Timestamp)
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
	"SrcMAC",       // string
	"DstMAC",       // string
	"EthernetType", // int32
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
