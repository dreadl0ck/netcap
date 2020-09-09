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
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var fieldsService = []string{
	"Timestamp",
	"IP",          // string
	"Port",        // int32
	"Name",        // string
	"Banner",      // string
	"Protocol",    // string
	"Flows",       // []string
	"Product",     // string
	"Vendor",      // string
	"Version",     // string
	"Notes",       // string
	"BytesServer", // int32
	"BytesClient", // int32
	"Hostname",    // string
	"OS",          // string
}

// CSVHeader returns the CSV header for the audit record.
func (a *Service) CSVHeader() []string {
	return filter(fieldsService)
}

// CSVRecord returns the CSV record for the audit record.
func (a *Service) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(a.Timestamp),
		a.IP,                       // string
		formatInt32(a.Port),        // int32
		a.Name,                     // string
		a.Banner,                   // string
		a.Protocol,                 // string
		join(a.Flows...),           // []string
		a.Product,                  // string
		a.Vendor,                   // string
		a.Version,                  // string
		formatInt32(a.BytesServer), // int32
		formatInt32(a.BytesClient), // int32
		a.Hostname,                 // string
		a.OS,                       // string
	})
}

// Time returns the timestamp associated with the audit record.
func (a *Service) Time() int64 {
	return a.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (a *Service) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	a.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(a)
}

var fieldsServiceMetric = []string{
	"IP",          // string
	"Port",        // int32
	"Name",        // string
	"Protocol",    // string
	"NumFlows",    // []string
	"Product",     // string
	"Vendor",      // string
	"Version",     // string
	"BytesServer", // int32
	"BytesClient", // int32
	"Hostname",    // string
	//"OS",          // string
}

var serviceMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_Service.String()),
		Help: Type_NC_Service.String() + " audit records",
	},
	fieldsServiceMetric,
)

func (a *Service) metricValues() []string {
	return []string{
		a.IP,
		formatInt32(a.Port),
		a.Name,
		a.Protocol,
		strconv.Itoa(len(a.Flows)),
		a.Product,
		a.Vendor,
		a.Version,
		formatInt32(a.BytesServer),
		formatInt32(a.BytesClient),
		a.Hostname,
		// a.OS,
	}
}

// Inc increments the metrics for the audit record.
func (a *Service) Inc() {
	serviceMetric.WithLabelValues(a.metricValues()...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (a *Service) SetPacketContext(*PacketContext) {}

// Src returns the source address of the audit record.
func (a *Service) Src() string {
	return a.IP
}

// Dst returns the destination address of the audit record.
func (a *Service) Dst() string {
	return ""
}
