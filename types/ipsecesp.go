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

var fieldsIPSecESP = []string{
	"Timestamp",
	"SPI",
	"Seq",
	"LenEncrypted",
	"SrcIP", // string
	"DstIP", // string
}

func (a IPSecESP) CSVHeader() []string {
	return filter(fieldsIPSecESP)
}

func (a IPSecESP) CSVRecord() []string {
	// prevent accessing nil pointer
	if a.Context == nil {
		a.Context = &PacketContext{}
	}
	return filter([]string{
		formatTimestamp(a.Timestamp),
		formatInt32(a.SPI),
		formatInt32(a.Seq),
		formatInt32(a.LenEncrypted),
		a.Context.SrcIP,
		a.Context.DstIP,
	})
}

func (a IPSecESP) Time() string {
	return a.Timestamp
}

func (a IPSecESP) JSON() (string, error) {
	return jsonMarshaler.MarshalToString(&a)
}

var ipSecEspMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_IPSecESP.String()),
		Help: Type_NC_IPSecESP.String() + " audit records",
	},
	fieldsIPSecESP[1:],
)

func init() {
	prometheus.MustRegister(ipSecEspMetric)
}

func (a IPSecESP) Inc() {
	ipSecEspMetric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

func (a *IPSecESP) SetPacketContext(ctx *PacketContext) {
	a.Context = ctx
}

func (a IPSecESP) Src() string {
	if a.Context != nil {
		return a.Context.SrcIP
	}
	return ""
}

func (a IPSecESP) Dst() string {
	if a.Context != nil {
		return a.Context.DstIP
	}
	return ""
}
