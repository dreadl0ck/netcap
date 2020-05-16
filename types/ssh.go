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

var fieldsSSH = []string{
	"Timestamp",
	"HASSH",
	"Flow" ,
	"Notes",
}

func (a SSH) CSVHeader() []string {
	return filter(fieldsSSH)
}

func (a SSH) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(a.Timestamp),
	})
}

func (a SSH) Time() string {
	return a.Timestamp
}

func (a SSH) JSON() (string, error) {
	return jsonMarshaler.MarshalToString(&a)
}

var sshMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_SSH.String()),
		Help: Type_NC_SSH.String() + " audit records",
	},
	fieldsSSH[1:],
)

func init() {
	prometheus.MustRegister(sshMetric)
}

func (a SSH) Inc() {
	sshMetric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

func (a *SSH) SetPacketContext(ctx *PacketContext) {}

// TODO: preserve source and destination mac adresses for SSH and return them here
func (a SSH) Src() string {
	return ""
}

// TODO: preserve source and destination mac adresses for SSH and return them here
func (a SSH) Dst() string {
	return ""
}
