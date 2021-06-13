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
	"github.com/dreadl0ck/netcap/encoder"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const fieldHASSH = "HASSH"

var fieldsSSH = []string{
	fieldTimestamp,
	fieldHASSH,
	fieldFlow,
	fieldNotes,
}

// CSVHeader returns the CSV header for the audit record.
func (a *SSH) CSVHeader() []string {
	return filter(fieldsSSH)
}

// CSVRecord returns the CSV record for the audit record.
func (a *SSH) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(a.Timestamp),
		a.HASSH,
		a.Flow,
		a.Notes,
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
	fieldHASSH,
	fieldFlow,
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
		fieldHASSH,
		fieldFlow,
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

var sshEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (a *SSH) Encode() []string {
	return filter([]string{
		sshEncoder.Int64(fieldTimestamp, a.Timestamp),
		sshEncoder.String(fieldHASSH, a.HASSH),
		sshEncoder.String(fieldFlow, a.Flow),
		sshEncoder.String(fieldNotes, a.Notes),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (a *SSH) Analyze() {

}

// NetcapType returns the type of the current audit record
func (a *SSH) NetcapType() Type {
	return Type_NC_SSH
}
