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

	"github.com/dreadl0ck/netcap/utils"
	"github.com/prometheus/client_golang/prometheus"
)

var fieldsSoftware = []string{
	"Timestamp",
}

// CSVHeader returns the CSV header for the audit record.
func (a *Software) CSVHeader() []string {
	return filter(fieldsSoftware)
}

// CSVRecord returns the CSV record for the audit record.
func (a *Software) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(a.Timestamp),
	})
}

// Time returns the timestamp associated with the audit record.
func (a *Software) Time() string {
	return a.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (a *Software) JSON() (string, error) {
	a.Timestamp = utils.TimeToUnixMilli(a.Timestamp)
	return jsonMarshaler.MarshalToString(a)
}

var softwareMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_Software.String()),
		Help: Type_NC_Software.String() + " audit records",
	},
	fieldsSoftware[1:],
)

// Inc increments the metrics for the audit record.
func (a *Software) Inc() {
	softwareMetric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (a *Software) SetPacketContext(*PacketContext) {}

// Src returns the source address of the audit record.
func (a *Software) Src() string {
	return ""
}

// Dst returns the destination address of the audit record.
func (a *Software) Dst() string {
	return ""
}
