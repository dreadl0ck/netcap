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

var fieldsSoftware = []string{
	"Timestamp",
}

func (a *Software) CSVHeader() []string {
	return filter(fieldsSoftware)
}

func (a *Software) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(a.Timestamp),
	})
}

func (a *Software) Time() string {
	return a.Timestamp
}

func (a *Software) JSON() (string, error) {
	return jsonMarshaler.MarshalToString(a)
}

var softwareMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_Software.String()),
		Help: Type_NC_Software.String() + " audit records",
	},
	fieldsSoftware[1:],
)

func init() {
	prometheus.MustRegister(softwareMetric)
}

func (a *Software) Inc() {
	softwareMetric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

func (a *Software) SetPacketContext(*PacketContext) {}

func (a *Software) Src() string {
	return ""
}

func (a *Software) Dst() string {
	return ""
}
