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

var fieldsIPv6HopByHop = []string{
	fieldTimestamp,
	fieldOptions,
	fieldSrcIP, // string
	fieldDstIP, // string
}

// CSVHeader returns the CSV header for the audit record.
func (l *IPv6HopByHop) CSVHeader() []string {
	return filter(fieldsIPv6HopByHop)
}

// CSVRecord returns the CSV record for the audit record.
func (l *IPv6HopByHop) CSVRecord() []string {
	opts := make([]string, len(l.Options))
	for i, v := range l.Options {
		opts[i] = v.toString()
	}

	return filter([]string{
		formatTimestamp(l.Timestamp),
		strings.Join(opts, ""),
		l.SrcIP,
		l.DstIP,
	})
}

// Time returns the timestamp associated with the audit record.
func (l *IPv6HopByHop) Time() int64 {
	return l.Timestamp
}

func (o *IPv6HopByHopOption) toString() string {
	var b strings.Builder
	b.WriteString(StructureBegin)
	b.WriteString(formatInt32(o.OptionType))        // int32
	b.WriteString(formatInt32(o.OptionLength))      // int32
	b.WriteString(formatInt32(o.ActualLength))      // int32
	b.WriteString(hex.EncodeToString(o.OptionData)) // []byte
	b.WriteString(o.OptionAlignment.toString())     //  *IPv6HopByHopOptionAlignment
	b.WriteString(StructureEnd)
	return b.String()
}

func (a *IPv6HopByHopOptionAlignment) toString() string {
	return join(formatInt32(a.One), formatInt32(a.Two))
}

// JSON returns the JSON representation of the audit record.
func (l *IPv6HopByHop) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	l.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(l)
}

var ip6hopMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_IPv6HopByHop.String()),
		Help: Type_NC_IPv6HopByHop.String() + " audit records",
	},
	fieldsIPv6HopByHop[1:],
)

// Inc increments the metrics for the audit record.
func (l *IPv6HopByHop) Inc() {
	ip6hopMetric.WithLabelValues(l.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (l *IPv6HopByHop) SetPacketContext(ctx *PacketContext) {
	l.SrcIP = ctx.SrcIP
	l.DstIP = ctx.DstIP
}

// Src returns the source address of the audit record.
func (l *IPv6HopByHop) Src() string {
	return l.SrcIP
}

// Dst returns the destination address of the audit record.
func (l *IPv6HopByHop) Dst() string {
	return l.DstIP
}

var ip6hopEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (l *IPv6HopByHop) Encode() []string {
	opts := make([]string, len(l.Options))
	for i, v := range l.Options {
		opts[i] = v.toString()
	}

	return filter([]string{
		ip6hopEncoder.Int64(fieldTimestamp, l.Timestamp),
		ip6hopEncoder.String(fieldOptions, strings.Join(opts, "")),
		ip6hopEncoder.String(fieldSrcIP, l.SrcIP),
		ip6hopEncoder.String(fieldDstIP, l.DstIP),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (l *IPv6HopByHop) Analyze() {}

// NetcapType returns the type of the current audit record
func (l *IPv6HopByHop) NetcapType() Type {
	return Type_NC_IPv6HopByHop
}
