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
	"encoding/hex"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

var fieldsICMPv6RouterSolicitation = []string{
	"Timestamp",
	"Options",
	"SrcIP",
	"DstIP",
}

func (i ICMPv6RouterSolicitation) CSVHeader() []string {
	return filter(fieldsICMPv6RouterSolicitation)
}

func (i ICMPv6RouterSolicitation) CSVRecord() []string {
	var opts []string
	for _, o := range i.Options {
		opts = append(opts, o.ToString())
	}
	// prevent accessing nil pointer
	if i.Context == nil {
		i.Context = &PacketContext{}
	}
	return filter([]string{
		formatTimestamp(i.Timestamp),
		strings.Join(opts, ""),
		i.Context.SrcIP,
		i.Context.DstIP,
	})
}

func (i ICMPv6RouterSolicitation) Time() string {
	return i.Timestamp
}

func (o ICMPv6Option) ToString() string {

	var b strings.Builder
	b.WriteString(Begin)
	b.WriteString(formatInt32(o.Type))
	b.WriteString(Separator)
	b.WriteString(hex.EncodeToString(o.Data))
	b.WriteString(End)

	return b.String()
}

func (a ICMPv6RouterSolicitation) JSON() (string, error) {
	return jsonMarshaler.MarshalToString(&a)
}

var icmp6rsMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_ICMPv6RouterSolicitation.String()),
		Help: Type_NC_ICMPv6RouterSolicitation.String() + " audit records",
	},
	fieldsICMPv6RouterSolicitation[1:],
)

func init() {
	prometheus.MustRegister(icmp6rsMetric)
}

func (a ICMPv6RouterSolicitation) Inc() {
	icmp6rsMetric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

func (a *ICMPv6RouterSolicitation) SetPacketContext(ctx *PacketContext) {
	a.Context = ctx
}

func (a ICMPv6RouterSolicitation) Src() string {
	if a.Context != nil {
		return a.Context.SrcIP
	}
	return ""
}

func (a ICMPv6RouterSolicitation) Dst() string {
	if a.Context != nil {
		return a.Context.DstIP
	}
	return ""
}
