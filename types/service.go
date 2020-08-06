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

var fieldsService = []string{
	"Timestamp",
}

func (a *Service) CSVHeader() []string {
	return filter(fieldsService)
}

func (a *Service) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(a.Timestamp),
	})
}

func (a *Service) Time() string {
	return a.Timestamp
}

func (a *Service) JSON() (string, error) {
	return jsonMarshaler.MarshalToString(a)
}

var serviceMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_Service.String()),
		Help: Type_NC_Service.String() + " audit records",
	},
	fieldsService[1:],
)

func init() {
	prometheus.MustRegister(serviceMetric)
}

func (a *Service) Inc() {
	serviceMetric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

func (a *Service) SetPacketContext(*PacketContext) {}

func (a *Service) Src() string {
	return ""
}

func (a *Service) Dst() string {
	return ""
}
