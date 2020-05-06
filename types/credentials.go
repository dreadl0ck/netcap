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

var fieldsCredentials = []string{
	"Timestamp",
}

func (a Credentials) CSVHeader() []string {
	return filter(fieldsCredentials)
}

func (a Credentials) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(a.Timestamp),
	})
}

func (a Credentials) Time() string {
	return a.Timestamp
}

func (a Credentials) JSON() (string, error) {
	return jsonMarshaler.MarshalToString(&a)
}

var credentialsMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_Credentials.String()),
		Help: Type_NC_Credentials.String() + " audit records",
	},
	fieldsCredentials[1:],
)

func init() {
	prometheus.MustRegister(credentialsMetric)
}

func (a Credentials) Inc() {
	credentialsMetric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

func (a *Credentials) SetPacketContext(ctx *PacketContext) {}

// TODO: preserve source and destination mac adresses for Credentials and return them here
func (a Credentials) Src() string {
	return ""
}

// TODO: preserve source and destination mac adresses for Credentials and return them here
func (a Credentials) Dst() string {
	return ""
}
