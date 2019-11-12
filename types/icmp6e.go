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

var fieldsICMPv6Echo = []string{
	"Timestamp",
	"Identifier", //  int32
	"SeqNumber",  //  int32
	"SrcIP",
	"DstIP",
}

func (i ICMPv6Echo) CSVHeader() []string {
	return filter([]string{
		"Timestamp",
		"Identifier", //  int32
		"SeqNumber",  //  int32
		i.Context.SrcIP,
		i.Context.DstIP,
	})

}

func (i ICMPv6Echo) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(i.Timestamp),
		formatInt32(i.Identifier),
		formatInt32(i.SeqNumber),
	})
}

func (i ICMPv6Echo) NetcapTimestamp() string {
	return i.Timestamp
}

func (a ICMPv6Echo) JSON() (string, error) {
	return jsonMarshaler.MarshalToString(&a)
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

func (a ICMPv6Echo) Inc() {
	icmp6eMetric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

func (a *ICMPv6Echo) SetPacketContext(ctx *PacketContext) {
	a.Context = ctx
}