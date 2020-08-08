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
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

var fieldsNortelDiscovery = []string{
	"Timestamp",
	"IPAddress", // string
	"SegmentID", // []byte
	"Chassis",   // int32
	"Backplane", // int32
	"State",     // int32
	"NumLinks",  // int32
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
func (a *NortelDiscovery) Time() string {
	return a.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (a *NortelDiscovery) JSON() (string, error) {
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
