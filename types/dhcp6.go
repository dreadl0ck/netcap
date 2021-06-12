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
	"github.com/dreadl0ck/netcap/encoder"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	fieldMsgType       = "MsgType"
	fieldHopCount      = "HopCount"
	fieldLinkAddr      = "LinkAddr"
	fieldPeerAddr      = "PeerAddr"
	fieldTransactionID = "TransactionID"
)

var fieldsDHCPv6 = []string{
	fieldTimestamp,     // string
	fieldMsgType,       // int32
	fieldHopCount,      // int32
	fieldLinkAddr,      // string
	fieldPeerAddr,      // string
	fieldTransactionID, // []byte
	//fieldOptions,       // []*DHCPv6Option
	fieldSrcIP,
	fieldDstIP,
	fieldSrcPort,
	fieldDstPort,
}

// CSVHeader returns the CSV header for the audit record.
func (d *DHCPv6) CSVHeader() []string {
	return filter(fieldsDHCPv6)
}

// CSVRecord returns the CSV record for the audit record.
func (d *DHCPv6) CSVRecord() []string {
	var opts []string
	for _, o := range d.Options {
		opts = append(opts, o.toString())
	}

	return filter([]string{
		formatTimestamp(d.Timestamp),        // string
		formatInt32(d.MsgType),              // int32
		formatInt32(d.HopCount),             // int32
		d.LinkAddr,                          // string
		d.PeerAddr,                          // string
		hex.EncodeToString(d.TransactionID), // []byte
		//strings.Join(opts, ""),              // []*DHCPv6Option
		d.SrcIP,
		d.DstIP,
		formatInt32(d.SrcPort),
		formatInt32(d.DstPort),
	})
}

// Time returns the timestamp associated with the audit record.
func (d *DHCPv6) Time() int64 {
	return d.Timestamp
}

func (d DHCPv6Option) toString() string {
	var b strings.Builder
	b.WriteString(StructureBegin)
	b.WriteString(formatInt32(d.Code))
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(d.Length))
	b.WriteString(FieldSeparator)
	b.WriteString(d.Data)
	b.WriteString(StructureEnd)
	return b.String()
}

// JSON returns the JSON representation of the audit record.
func (d *DHCPv6) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	d.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(d)
}

var fieldsDHCPv6Metric = []string{
	fieldMsgType,  // int32
	fieldHopCount, // int32
	fieldLinkAddr, // string
	fieldPeerAddr, // string
	fieldSrcIP,
	fieldDstIP,
	fieldSrcPort,
	fieldDstPort,
}

var dhcp6Metric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_DHCPv6.String()),
		Help: Type_NC_DHCPv6.String() + " audit records",
	},
	fieldsDHCPv6Metric,
)

func (d *DHCPv6) metricValues() []string {
	return []string{
		formatInt32(d.MsgType),  // int32
		formatInt32(d.HopCount), // int32
		d.LinkAddr,              // string
		d.PeerAddr,              // string
		d.SrcIP,
		d.DstIP,
		formatInt32(d.SrcPort),
		formatInt32(d.DstPort),
	}
}

// Inc increments the metrics for the audit record.
func (d *DHCPv6) Inc() {
	dhcp6Metric.WithLabelValues(d.metricValues()...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (d *DHCPv6) SetPacketContext(ctx *PacketContext) {
	d.SrcIP = ctx.SrcIP
	d.DstIP = ctx.DstIP
	d.SrcPort = ctx.SrcPort
	d.DstPort = ctx.DstPort
}

// Src returns the source address of the audit record.
func (d *DHCPv6) Src() string {
	return d.SrcIP
}

// Dst returns the destination address of the audit record.
func (d *DHCPv6) Dst() string {
	return d.DstIP
}

var dhcp6Encoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (d *DHCPv6) Encode() []string {

	var opts []string
	for _, o := range d.Options {
		opts = append(opts, o.toString())
	}

	return filter([]string{
		dhcp6Encoder.Int64(fieldTimestamp, d.Timestamp),                              // int64
		dhcp6Encoder.Int32(fieldMsgType, d.MsgType),                                  // int32
		dhcp6Encoder.Int32(fieldHopCount, d.HopCount),                                // int32
		dhcp6Encoder.String(fieldLinkAddr, d.LinkAddr),                               // string
		dhcp6Encoder.String(fieldPeerAddr, d.PeerAddr),                               // string
		dhcp4Encoder.String(fieldTransactionID, hex.EncodeToString(d.TransactionID)), // []byte
		dhcp4Encoder.String(fieldSrcIP, d.SrcIP),
		dhcp4Encoder.String(fieldDstIP, d.DstIP),
		dhcp4Encoder.Int32(fieldSrcPort, d.SrcPort),
		dhcp4Encoder.Int32(fieldDstPort, d.DstPort),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (d *DHCPv6) Analyze() {
}

// NetcapType returns the type of the current audit record
func (d *DHCPv6) NetcapType() Type {
	return Type_NC_DHCPv6
}
