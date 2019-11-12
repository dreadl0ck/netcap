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

var fieldsEthernetCTP = []string{
	"Timestamp",
	"SkipCount", // int32
}

func (i EthernetCTP) CSVHeader() []string {
	return filter(fieldsEthernetCTP)
}

func (i EthernetCTP) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(i.Timestamp),
		formatInt32(i.SkipCount),
	})
}

func (i EthernetCTP) NetcapTimestamp() string {
	return i.Timestamp
}

func (a EthernetCTP) JSON() (string, error) {
	return jsonMarshaler.MarshalToString(&a)
}

var ethernetCTPMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_EthernetCTP.String()),
		Help: Type_NC_EthernetCTP.String() + " audit records",
	},
	fieldsEthernetCTP[1:],
)

func init() {
	prometheus.MustRegister(ethernetCTPMetric)
}

func (a EthernetCTP) Inc() {
	ethernetCTPMetric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

func (a *EthernetCTP) SetPacketContext(ctx *PacketContext) {}
