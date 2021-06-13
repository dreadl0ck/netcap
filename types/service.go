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
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	fieldIP          = "IP"
	fieldPort        = "Port"
	fieldBanner      = "Banner"
	fieldNumFlows    = "NumFlows"
	fieldProduct     = "Product"
	fieldVendor      = "Vendor"
	fieldBytesServer = "BytesServer"
	fieldBytesClient = "BytesClient"
	fieldHostname    = "Hostname"
	fieldOS          = "OS"
)

var fieldsService = []string{
	fieldTimestamp,
	fieldIP,          // string
	fieldPort,        // int32
	fieldName,        // string
	fieldBanner,      // string
	fieldProtocol,    // string
	fieldNumFlows,    // []string
	fieldProduct,     // string
	fieldVendor,      // string
	fieldVersion,     // string
	fieldNotes,       // string
	fieldBytesServer, // int32
	fieldBytesClient, // int32
	fieldHostname,    // string
	fieldOS,          // string
}

// CSVHeader returns the CSV header for the audit record.
func (a *Service) CSVHeader() []string {
	return filter(fieldsService)
}

// CSVRecord returns the CSV record for the audit record.
func (a *Service) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(a.Timestamp),
		a.IP,                                // string
		formatInt32(a.Port),                 // int32
		a.Name,                              // string
		a.Banner,                            // string
		a.Protocol,                          // string
		strconv.Itoa(len(join(a.Flows...))), // []string
		a.Product,                           // string
		a.Vendor,                            // string
		a.Version,                           // string
		formatInt32(a.BytesServer),          // int32
		formatInt32(a.BytesClient),          // int32
		a.Hostname,                          // string
		a.OS,                                // string
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
	fieldIP,          // string
	fieldPort,        // int32
	fieldName,        // string
	fieldProtocol,    // string
	fieldNumFlows,    // []string
	fieldProduct,     // string
	fieldVendor,      // string
	fieldVersion,     // string
	fieldBytesServer, // int32
	fieldBytesClient, // int32
	fieldHostname,    // string
	//fieldOS,          // string
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

var serviceEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (a *Service) Encode() []string {
	return filter([]string{
		serviceEncoder.Int64(fieldTimestamp, a.Timestamp),
		serviceEncoder.String(fieldIP, a.IP),                  // string
		serviceEncoder.Int32(fieldPort, a.Port),               // int32
		serviceEncoder.String(fieldName, a.Name),              // string
		serviceEncoder.String(fieldBanner, a.Banner),          // string
		serviceEncoder.String(fieldProtocol, a.Protocol),      // string
		serviceEncoder.Int(fieldNumFlows, len(a.Flows)),       // []string
		serviceEncoder.String(fieldProduct, a.Product),        // string
		serviceEncoder.String(fieldVendor, a.Vendor),          // string
		serviceEncoder.String(fieldVersion, a.Version),        // string
		serviceEncoder.Int32(fieldBytesServer, a.BytesServer), // int32
		serviceEncoder.Int32(fieldBytesClient, a.BytesClient), // int32
		serviceEncoder.String(fieldHostname, a.Hostname),      // string
		serviceEncoder.String(fieldOS, a.OS),                  // string
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (a *Service) Analyze() {}

// NetcapType returns the type of the current audit record
func (a *Service) NetcapType() Type {
	return Type_NC_Service
}
