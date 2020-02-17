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

var fieldsIPv6HopByHop = []string{
	"Timestamp",
	"Options",
	"SrcIP", // string
	"DstIP", // string
}

func (l IPv6HopByHop) CSVHeader() []string {
	return filter(fieldsIPv6HopByHop)
}

func (l IPv6HopByHop) CSVRecord() []string {
	opts := make([]string, len(l.Options))
	for i, v := range l.Options {
		opts[i] = v.ToString()
	}
	// prevent accessing nil pointer
	if l.Context == nil {
		l.Context = &PacketContext{}
	}
	return filter([]string{
		formatTimestamp(l.Timestamp),
		strings.Join(opts, ""),
		l.Context.SrcIP,
		l.Context.DstIP,
	})
}

func (l IPv6HopByHop) Time() string {
	return l.Timestamp
}

func (o IPv6HopByHopOption) ToString() string {
	var b strings.Builder
	b.WriteString(Begin)
	b.WriteString(formatInt32(o.OptionType))        // int32
	b.WriteString(formatInt32(o.OptionLength))      // int32
	b.WriteString(formatInt32(o.ActualLength))      // int32
	b.WriteString(hex.EncodeToString(o.OptionData)) // []byte
	b.WriteString(o.OptionAlignment.ToString())     //  *IPv6HopByHopOptionAlignment
	b.WriteString(End)
	return b.String()
}

func (a IPv6HopByHopOptionAlignment) ToString() string {
	return join(formatInt32(a.One), formatInt32(a.Two))
}

func (a IPv6HopByHop) JSON() (string, error) {
	return jsonMarshaler.MarshalToString(&a)
}

var ip6hopMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_IPv6HopByHop.String()),
		Help: Type_NC_IPv6HopByHop.String() + " audit records",
	},
	fieldsIPv6HopByHop[1:],
)

func init() {
	prometheus.MustRegister(ip6hopMetric)
}

func (a IPv6HopByHop) Inc() {
	ip6hopMetric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

func (a *IPv6HopByHop) SetPacketContext(ctx *PacketContext) {
	a.Context = ctx
}

func (a IPv6HopByHop) Src() string {
	if a.Context != nil {
		return a.Context.SrcIP
	}
	return ""
}

func (a IPv6HopByHop) Dst() string {
	if a.Context != nil {
		return a.Context.DstIP
	}
	return ""
}
