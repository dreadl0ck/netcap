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
	"time"

	"github.com/dreadl0ck/netcap/encoder"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	fieldTimestampFirst      = "TimestampFirst"
	fieldLinkProto           = "LinkProto"
	fieldNetworkProto        = "NetworkProto"
	fieldTransportProto      = "TransportProto"
	fieldApplicationProto    = "ApplicationProto"
	fieldTotalSize           = "TotalSize"
	fieldAppPayloadSize      = "AppPayloadSize"
	fieldNumPackets          = "NumPackets"
	fieldUID                 = "UID"
	fieldDuration            = "Duration"
	fieldTimestampLast       = "TimestampLast"
	fieldBytesClientToServer = "BytesClientToServer"
	fieldBytesServerToClient = "BytesServerToClient"
	fieldNumFINFlags         = "NumFINFlags"
	fieldNumRSTFlags         = "NumRSTFlags"
	fieldNumACKFlags         = "NumACKFlags"
	fieldNumSYNFlags         = "NumSYNFlags"
	fieldNumURGFlags         = "NumURGFlags"
	fieldNumECEFlags         = "NumECEFlags"
	fieldNumPSHFlags         = "NumPSHFlags"
	fieldNumCWRFlags         = "NumCWRFlags"
	fieldNumNSFlags          = "NumNSFlags"
	fieldMeanWindowSize      = "MeanWindowSize"
)

var fieldsConnection = []string{
	fieldTimestampFirst,
	fieldLinkProto,
	fieldNetworkProto,
	fieldTransportProto,
	fieldApplicationProto,
	fieldSrcMAC,
	fieldDstMAC,
	fieldSrcIP,
	fieldSrcPort,
	fieldDstIP,
	fieldDstPort,
	fieldTotalSize,
	fieldAppPayloadSize,
	fieldNumPackets,
	//fieldUID,
	fieldDuration,
	fieldTimestampLast,
	fieldBytesClientToServer,
	fieldBytesServerToClient,
	fieldNumFINFlags,
	fieldNumRSTFlags,
	fieldNumACKFlags,
	fieldNumSYNFlags,
	fieldNumURGFlags,
	fieldNumECEFlags,
	fieldNumPSHFlags,
	fieldNumCWRFlags,
	fieldNumNSFlags,
	fieldMeanWindowSize,
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
		//c.UID,
		formatInt64(c.Duration),
		formatTimestamp(c.TimestampLast),
		formatInt64(c.BytesClientToServer),
		formatInt64(c.BytesServerToClient),
		formatInt32(c.NumFINFlags),
		formatInt32(c.NumRSTFlags),
		formatInt32(c.NumACKFlags),
		formatInt32(c.NumSYNFlags),
		formatInt32(c.NumURGFlags),
		formatInt32(c.NumECEFlags),
		formatInt32(c.NumPSHFlags),
		formatInt32(c.NumCWRFlags),
		formatInt32(c.NumNSFlags),
		formatInt32(c.MeanWindowSize),
	})
}

// Time returns the timestamp associated with the audit record.
func (c *Connection) Time() int64 {
	return c.TimestampFirst
}

// JSON returns the JSON representation of the audit record.
func (c *Connection) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	c.TimestampFirst /= int64(time.Millisecond)
	c.TimestampLast /= int64(time.Millisecond)

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
	fieldLinkProto,
	fieldNetworkProto,
	fieldTransportProto,
	fieldApplicationProto,
	fieldSrcMAC,
	fieldDstMAC,
	fieldSrcIP,
	fieldSrcPort,
	fieldDstIP,
	fieldDstPort,
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

var connectionEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (c *Connection) Encode() []string {
	return filter([]string{
		connectionEncoder.Int64(fieldTimestampFirst, c.TimestampFirst),
		connectionEncoder.String(fieldLinkProto, c.LinkProto),
		connectionEncoder.String(fieldNetworkProto, c.NetworkProto),
		connectionEncoder.String(fieldTransportProto, c.TransportProto),
		connectionEncoder.String(fieldApplicationProto, c.ApplicationProto),
		connectionEncoder.Uint64(fieldSrcMAC, macToUint64(c.SrcMAC)),
		connectionEncoder.Uint64(fieldDstMAC, macToUint64(c.DstMAC)),
		connectionEncoder.Int64(fieldSrcIP, ipToInt64(c.SrcIP)),
		connectionEncoder.Int(fieldSrcPort, portToInt(c.SrcPort)),
		connectionEncoder.Int64(fieldDstIP, ipToInt64(c.DstIP)),
		connectionEncoder.Int(fieldDstPort, portToInt(c.DstPort)),
		connectionEncoder.Int32(fieldTotalSize, c.TotalSize),
		connectionEncoder.Int32(fieldAppPayloadSize, c.AppPayloadSize),
		connectionEncoder.Int32(fieldNumPackets, c.NumPackets),
		//connectionEncoder.String(fieldUID, c.UID),
		connectionEncoder.Int64(fieldDuration, c.Duration),
		connectionEncoder.Int64(fieldTimestampLast, c.TimestampLast),
		connectionEncoder.Int64(fieldBytesClientToServer, c.BytesClientToServer),
		connectionEncoder.Int64(fieldBytesServerToClient, c.BytesServerToClient),
		connectionEncoder.Int32(fieldNumFINFlags, c.NumFINFlags),
		connectionEncoder.Int32(fieldNumRSTFlags, c.NumRSTFlags),
		connectionEncoder.Int32(fieldNumACKFlags, c.NumACKFlags),
		connectionEncoder.Int32(fieldNumSYNFlags, c.NumSYNFlags),
		connectionEncoder.Int32(fieldNumURGFlags, c.NumURGFlags),
		connectionEncoder.Int32(fieldNumECEFlags, c.NumECEFlags),
		connectionEncoder.Int32(fieldNumPSHFlags, c.NumPSHFlags),
		connectionEncoder.Int32(fieldNumCWRFlags, c.NumCWRFlags),
		connectionEncoder.Int32(fieldNumNSFlags, c.NumNSFlags),
		connectionEncoder.Int32(fieldMeanWindowSize, c.MeanWindowSize),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (c *Connection) Analyze() {

}

// NetcapType returns the type of the current audit record
func (c *Connection) NetcapType() Type {
	return Type_NC_Connection
}
