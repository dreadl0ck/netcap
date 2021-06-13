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
	fieldTypeCode = "TypeCode"
)

var fieldsICMPv4 = []string{
	fieldTimestamp,
	fieldTypeCode, // int32
	fieldChecksum, // int32
	fieldId,       // int32
	fieldSeq,      // int32
	fieldSrcIP,
	fieldDstIP,
}

// CSVHeader returns the CSV header for the audit record.
func (i *ICMPv4) CSVHeader() []string {
	return filter(fieldsICMPv4)
}

// CSVRecord returns the CSV record for the audit record.
func (i *ICMPv4) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(i.Timestamp),
		formatInt32(i.TypeCode),
		formatInt32(i.Checksum),
		formatInt32(i.Id),
		formatInt32(i.Seq),
		i.SrcIP,
		i.DstIP,
	})
}

// Time returns the timestamp associated with the audit record.
func (i *ICMPv4) Time() int64 {
	return i.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (i *ICMPv4) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	i.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(i)
}

var icmp4Metric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_ICMPv4.String()),
		Help: Type_NC_ICMPv4.String() + " audit records",
	},
	fieldsICMPv4[1:],
)

// Inc increments the metrics for the audit record.
func (i *ICMPv4) Inc() {
	icmp4Metric.WithLabelValues(i.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (i *ICMPv4) SetPacketContext(ctx *PacketContext) {
	i.SrcIP = ctx.SrcIP
	i.DstIP = ctx.DstIP
}

// Src returns the source address of the audit record.
func (i *ICMPv4) Src() string {
	return i.SrcIP
}

// Dst returns the destination address of the audit record.
func (i *ICMPv4) Dst() string {
	return i.DstIP
}

var icmp4Encoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (i *ICMPv4) Encode() []string {
	return filter([]string{
		icmp4Encoder.Int64(fieldTimestamp, i.Timestamp),
		icmp4Encoder.Int32(fieldTypeCode, i.TypeCode),
		icmp4Encoder.Int32(fieldChecksum, i.Checksum),
		icmp4Encoder.Int32(fieldId, i.Id),
		icmp4Encoder.Int32(fieldSeq, i.Seq),
		icmp4Encoder.String(fieldSrcIP, i.SrcIP),
		icmp4Encoder.String(fieldDstIP, i.DstIP),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (i *ICMPv4) Analyze() {}

// NetcapType returns the type of the current audit record
func (i *ICMPv4) NetcapType() Type {
	return Type_NC_ICMPv4
}
