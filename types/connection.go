/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
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

func (c Connection) CSVHeader() []string {
	return filter(fieldsConnection)
}

func (c Connection) CSVRecord() []string {
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

func (c Connection) NetcapTimestamp() string {
	return c.TimestampFirst
}

func (a Connection) JSON() (string, error) {
	return jsonMarshaler.MarshalToString(&a)
}

var connectionsMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_Connection.String()),
		Help: Type_NC_Connection.String() + " audit records",
	},
	fieldsConnection,
)

func init() {
	prometheus.MustRegister(connectionsMetric)
}

func (a Connection) Inc() {
	connectionsMetric.WithLabelValues(a.CSVRecord()...).Inc()
}
