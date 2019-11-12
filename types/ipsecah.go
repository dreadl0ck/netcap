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

var fieldsIPSecAH = []string{
	"Timestamp",
	"Reserved",
	"SPI",
	"Seq",
	"AuthenticationData",
	"SrcIP", // string
	"DstIP", // string
}

func (a IPSecAH) CSVHeader() []string {
	return filter(fieldsIPSecAH)
}

func (a IPSecAH) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(a.Timestamp),
		formatInt32(a.Reserved),
		formatInt32(a.SPI),
		formatInt32(a.Seq),
		hex.EncodeToString(a.AuthenticationData),
		a.Context.SrcIP,
		a.Context.DstIP,
	})
}

func (a IPSecAH) NetcapTimestamp() string {
	return a.Timestamp
}

func (a IPSecAH) JSON() (string, error) {
	return jsonMarshaler.MarshalToString(&a)
}

var ipSecAhMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_IPSecAH.String()),
		Help: Type_NC_IPSecAH.String() + " audit records",
	},
	fieldsIPSecAH[1:],
)

func init() {
	prometheus.MustRegister(ipSecAhMetric)
}

func (a IPSecAH) Inc() {
	ipSecAhMetric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

func (a *IPSecAH) SetPacketContext(ctx *PacketContext) {
	a.Context = ctx
}
