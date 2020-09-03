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
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var fieldsSSH = []string{
	"Timestamp",
	"HASSH",
	"Flow",
	"Notes",
}

// CSVHeader returns the CSV header for the audit record.
func (a *SSH) CSVHeader() []string {
	return filter(fieldsSSH)
}

// CSVRecord returns the CSV record for the audit record.
func (a *SSH) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(a.Timestamp),
	})
}

// Time returns the timestamp associated with the audit record.
func (a *SSH) Time() int64 {
	return a.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (a *SSH) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	a.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(a)
}

var fieldsSSHMetric = []string{
	"HASSH",
	"Flow",
}

var sshMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_SSH.String()),
		Help: Type_NC_SSH.String() + " audit records",
	},
	fieldsSSHMetric,
)

func (a *SSH) metricValues() []string {
	return []string{
		"HASSH",
		"Flow",
	}
}

// Inc increments the metrics for the audit record.
func (a *SSH) Inc() {
	sshMetric.WithLabelValues(a.metricValues()...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (a *SSH) SetPacketContext(*PacketContext) {}

// Src TODO: preserve source and destination mac adresses for SSH and return them here.
// Src returns the source address of the audit record.
func (a *SSH) Src() string {
	return ""
}

// Dst TODO: preserve source and destination mac adresses for SSH and return them here.
// Dst returns the destination address of the audit record.
func (a *SSH) Dst() string {
	return ""
}
