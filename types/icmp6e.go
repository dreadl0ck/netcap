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

var fieldsICMPv6Echo = []string{
	"Timestamp",
	"Identifier", //  int32
	"SeqNumber",  //  int32
	"SrcIP",
	"DstIP",
}

// CSVHeader returns the CSV header for the audit record.
func (i *ICMPv6Echo) CSVHeader() []string {
	return filter(fieldsICMPv6Echo)
}

// CSVRecord returns the CSV record for the audit record.
func (i *ICMPv6Echo) CSVRecord() []string {
	// prevent accessing nil pointer
	if i.Context == nil {
		i.Context = &PacketContext{}
	}
	return filter([]string{
		formatTimestamp(i.Timestamp),
		formatInt32(i.Identifier),
		formatInt32(i.SeqNumber),
		i.Context.SrcIP,
		i.Context.DstIP,
	})
}

// Time returns the timestamp associated with the audit record.
func (i *ICMPv6Echo) Time() string {
	return i.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (i *ICMPv6Echo) JSON() (string, error) {
	return jsonMarshaler.MarshalToString(i)
}

var icmp6eMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_ICMPv6Echo.String()),
		Help: Type_NC_ICMPv6Echo.String() + " audit records",
	},
	fieldsICMPv6Echo[1:],
)

func init() {
	prometheus.MustRegister(icmp6eMetric)
}

// Inc increments the metrics for the audit record.
func (i *ICMPv6Echo) Inc() {
	icmp6eMetric.WithLabelValues(i.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (i *ICMPv6Echo) SetPacketContext(ctx *PacketContext) {
	i.Context = ctx
}

// Src returns the source address of the audit record.
func (i *ICMPv6Echo) Src() string {
	if i.Context != nil {
		return i.Context.SrcIP
	}
	return ""
}

// Dst returns the destination address of the audit record.
func (i *ICMPv6Echo) Dst() string {
	if i.Context != nil {
		return i.Context.DstIP
	}
	return ""
}
