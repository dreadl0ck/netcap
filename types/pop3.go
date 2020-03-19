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

var fieldsPOP3 = []string{
	"Timestamp",
}

func (a POP3) CSVHeader() []string {
	return filter(fieldsPOP3)
}

func (a POP3) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(a.Timestamp),
	})
}

func (a POP3) Time() string {
	return a.Timestamp
}

func (a POP3) JSON() (string, error) {
	return jsonMarshaler.MarshalToString(&a)
}

var pop3Metric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_POP3.String()),
		Help: Type_NC_POP3.String() + " audit records",
	},
	fieldsPOP3[1:],
)

func init() {
	prometheus.MustRegister(pop3Metric)
}

func (a POP3) Inc() {
	pop3Metric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

func (a *POP3) SetPacketContext(ctx *PacketContext) {}

// TODO: preserve source and destination mac adresses for POP3 and return them here
func (a POP3) Src() string {
	return ""
}

// TODO: preserve source and destination mac adresses for POP3 and return them here
func (a POP3) Dst() string {
	return ""
}
