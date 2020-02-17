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

var fieldsICMPv6 = []string{
	"Timestamp",
	"TypeCode", // int32
	"Checksum", // int32
	"SrcIP",
	"DstIP",
}

func (i ICMPv6) CSVHeader() []string {
	return filter(fieldsICMPv6)
}

func (i ICMPv6) CSVRecord() []string {
	// prevent accessing nil pointer
	if i.Context == nil {
		i.Context = &PacketContext{}
	}
	return filter([]string{
		formatTimestamp(i.Timestamp),
		formatInt32(i.TypeCode),
		formatInt32(i.Checksum),
		i.Context.SrcIP,
		i.Context.DstIP,
	})
}

func (i ICMPv6) Time() string {
	return i.Timestamp
}

func (a ICMPv6) JSON() (string, error) {
	return jsonMarshaler.MarshalToString(&a)
}

var icmp6Metric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_ICMPv6.String()),
		Help: Type_NC_ICMPv6.String() + " audit records",
	},
	fieldsICMPv6[1:],
)

func init() {
	prometheus.MustRegister(icmp6Metric)
}

func (a ICMPv6) Inc() {
	icmp6Metric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

func (a *ICMPv6) SetPacketContext(ctx *PacketContext) {
	a.Context = ctx
}

func (a ICMPv6) Src() string {
	if a.Context != nil {
		return a.Context.SrcIP
	}
	return ""
}

func (a ICMPv6) Dst() string {
	if a.Context != nil {
		return a.Context.DstIP
	}
	return ""
}
