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

var fieldsConnection = []string{
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
func (c *Connection) CSVHeader() []string {
	return filter(fieldsConnection)
}

// CSVRecord returns the CSV record for the audit record.
func (c *Connection) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(c.TimestampFirst),
		c.LinkProto,
		c.NetworkProto,
		c.TransportProto,
		c.ApplicationProto,
		c.SrcMAC,
		c.DstMAC,
		c.SrcIP,
		c.SrcPort,
		c.DstIP,
		c.DstPort,
		formatInt32(c.TotalSize),
		formatInt32(c.AppPayloadSize),
		formatInt32(c.NumPackets),
		c.UID,
		formatInt64(c.Duration),
		formatTimestamp(c.TimestampLast),
	})
}

// Time returns the timestamp associated with the audit record.
func (c *Connection) Time() int64 {
	return c.TimestampFirst
}

// JSON returns the JSON representation of the audit record.
func (c *Connection) JSON() (string, error) {
	//c.TimestampFirst = utils.TimeToUnixMilli(c.TimestampFirst)
	//c.TimestampLast = utils.TimeToUnixMilli(c.TimestampLast)

	return jsonMarshaler.MarshalToString(c)
}

var (
	connectionsMetric = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: strings.ToLower(Type_NC_Connection.String()),
			Help: Type_NC_Connection.String() + " audit records",
		},
		fieldsConnectionMetrics,
	)
	connTotalSize = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    strings.ToLower(Type_NC_Connection.String()) + "_size",
			Help:    Type_NC_Connection.String() + " payload entropy",
			Buckets: prometheus.LinearBuckets(20, 5, 5),
		},
		[]string{"SrcMAC", "DstMAC"},
	)
	connAppPayloadSize = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    strings.ToLower(Type_NC_Connection.String()) + "_payload_size",
			Help:    Type_NC_Connection.String() + " payload sizes",
			Buckets: prometheus.LinearBuckets(20, 5, 5),
		},
		[]string{"SrcMAC", "DstMAC"},
	)
	connNumPackets = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    strings.ToLower(Type_NC_Connection.String()) + "_numpackets",
			Help:    Type_NC_Connection.String() + " payload sizes",
			Buckets: prometheus.LinearBuckets(20, 5, 5),
		},
		[]string{"SrcMAC", "DstMAC"},
	)
	connDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    strings.ToLower(Type_NC_Connection.String()) + "_duration",
			Help:    Type_NC_Connection.String() + " payload sizes",
			Buckets: prometheus.LinearBuckets(20, 5, 5),
		},
		[]string{"SrcMAC", "DstMAC"},
	)
)

var fieldsConnectionMetrics = []string{
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

func (c *Connection) metricValues() []string {
	return []string{
		c.LinkProto,
		c.NetworkProto,
		c.TransportProto,
		c.ApplicationProto,
		c.SrcMAC,
		c.DstMAC,
		c.SrcIP,
		c.SrcPort,
		c.DstIP,
		c.DstPort,
	}
}

// Inc increments the metrics for the audit record.
func (c *Connection) Inc() {
	connectionsMetric.WithLabelValues(c.metricValues()...).Inc()
	connTotalSize.WithLabelValues(c.SrcMAC, c.DstMAC).Observe(float64(c.TotalSize))
	connAppPayloadSize.WithLabelValues(c.SrcMAC, c.DstMAC).Observe(float64(c.AppPayloadSize))
	connNumPackets.WithLabelValues(c.SrcMAC, c.DstMAC).Observe(float64(c.NumPackets))
	connDuration.WithLabelValues(c.SrcMAC, c.DstMAC).Observe(float64(c.Duration))
}

// SetPacketContext sets the associated packet context for the audit record.
func (c *Connection) SetPacketContext(*PacketContext) {}

// Src returns the source address of the audit record.
func (c *Connection) Src() string {
	return c.SrcIP
}

// Dst returns the destination address of the audit record.
func (c *Connection) Dst() string {
	return c.DstIP
}
