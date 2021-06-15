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
	"encoding/hex"
	"github.com/dreadl0ck/netcap/encoder"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	fieldIPAddress = "IPAddress"
	fieldSegmentID = "SegmentID"
	fieldChassis   = "Chassis"
	fieldBackplane = "Backplane"
	fieldNumLinks  = "NumLinks"
)

var fieldsNortelDiscovery = []string{
	fieldTimestamp,
	fieldIPAddress, // string
	fieldSegmentID, // []byte
	fieldChassis,   // int32
	fieldBackplane, // int32
	fieldState,     // int32
	fieldNumLinks,  // int32
}

// CSVHeader returns the CSV header for the audit record.
func (a *NortelDiscovery) CSVHeader() []string {
	return filter(fieldsNortelDiscovery)
}

// CSVRecord returns the CSV record for the audit record.
func (a *NortelDiscovery) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(a.Timestamp),
		a.IPAddress,                     // string
		hex.EncodeToString(a.SegmentID), // []byte
		formatInt32(a.Chassis),          // int32
		formatInt32(a.Backplane),        // int32
		formatInt32(a.State),            // int32
		formatInt32(a.NumLinks),         // int32
	})
}

// Time returns the timestamp associated with the audit record.
func (a *NortelDiscovery) Time() int64 {
	return a.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (a *NortelDiscovery) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	a.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(a)
}

var nortelDiscoveryMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_NortelDiscovery.String()),
		Help: Type_NC_NortelDiscovery.String() + " audit records",
	},
	fieldsNortelDiscovery[1:],
)

// Inc increments the metrics for the audit record.
func (a *NortelDiscovery) Inc() {
	nortelDiscoveryMetric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (a *NortelDiscovery) SetPacketContext(*PacketContext) {}

// Src TODO.
// Src returns the source address of the audit record.
func (a *NortelDiscovery) Src() string {
	return ""
}

// Dst returns the destination address of the audit record.
func (a *NortelDiscovery) Dst() string {
	return ""
}

var nortelDiscoveryEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (a *NortelDiscovery) Encode() []string {
	return filter([]string{
		nortelDiscoveryEncoder.Int64(fieldTimestamp, a.Timestamp),
		nortelDiscoveryEncoder.String(fieldIPAddress, a.IPAddress),                     // string
		nortelDiscoveryEncoder.String(fieldSegmentID, hex.EncodeToString(a.SegmentID)), // []byte
		nortelDiscoveryEncoder.Int32(fieldChassis, a.Chassis),                          // int32
		nortelDiscoveryEncoder.Int32(fieldBackplane, a.Backplane),                      // int32
		nortelDiscoveryEncoder.Int32(fieldState, a.State),                              // int32
		nortelDiscoveryEncoder.Int32(fieldNumLinks, a.NumLinks),                        // int32
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (a *NortelDiscovery) Analyze() {}

// NetcapType returns the type of the current audit record
func (a *NortelDiscovery) NetcapType() Type {
	return Type_NC_NortelDiscovery
}
