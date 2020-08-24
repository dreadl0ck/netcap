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

	"github.com/dreadl0ck/netcap/utils"
)

var fieldsService = []string{
	"Timestamp",
}

// CSVHeader returns the CSV header for the audit record.
func (a *Service) CSVHeader() []string {
	return filter(fieldsService)
}

// CSVRecord returns the CSV record for the audit record.
func (a *Service) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(a.Timestamp),
	})
}

// Time returns the timestamp associated with the audit record.
func (a *Service) Time() string {
	return a.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (a *Service) JSON() (string, error) {
	a.Timestamp = utils.TimeToUnixMilli(a.Timestamp)
	return jsonMarshaler.MarshalToString(a)
}

var serviceMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_Service.String()),
		Help: Type_NC_Service.String() + " audit records",
	},
	fieldsService[1:],
)

// Inc increments the metrics for the audit record.
func (a *Service) Inc() {
	serviceMetric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (a *Service) SetPacketContext(*PacketContext) {}

// Src returns the source address of the audit record.
func (a *Service) Src() string {
	return ""
}

// Dst returns the destination address of the audit record.
func (a *Service) Dst() string {
	return ""
}
