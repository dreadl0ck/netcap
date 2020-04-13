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

var fieldsICMPv4 = []string{
	"Timestamp",
	"TypeCode", // int32
	"Checksum", // int32
	"Id",       // int32
	"Seq",      // int32
	"SrcIP",
	"DstIP",
}

func (i ICMPv4) CSVHeader() []string {
	return filter(fieldsICMPv4)
}

func (i ICMPv4) CSVRecord() []string {
	// prevent accessing nil pointer
	if i.Context == nil {
		i.Context = &PacketContext{}
	}
	return filter([]string{
		formatTimestamp(i.Timestamp),
		formatInt32(i.TypeCode),
		formatInt32(i.Checksum),
		formatInt32(i.Id),
		formatInt32(i.Seq),
		i.Context.SrcIP,
		i.Context.DstIP,
	})
}

func (i ICMPv4) Time() string {
	return i.Timestamp
}

func (a ICMPv4) JSON() (string, error) {
	return jsonMarshaler.MarshalToString(&a)
}

var icmp4Metric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_ICMPv4.String()),
		Help: Type_NC_ICMPv4.String() + " audit records",
	},
	fieldsICMPv4[1:],
)

func init() {
	prometheus.MustRegister(icmp4Metric)
}

func (a ICMPv4) Inc() {
	icmp4Metric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

func (a *ICMPv4) SetPacketContext(ctx *PacketContext) {
	a.Context = ctx
}

func (a ICMPv4) Src() string {
	if a.Context != nil {
		return a.Context.SrcIP
	}
	return ""
}

func (a ICMPv4) Dst() string {
	if a.Context != nil {
		return a.Context.DstIP
	}
	return ""
}
