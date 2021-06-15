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
	fieldTTL      = "TTL"
	fieldChecksum = "Checksum"
	fieldValues   = "Values"
)

var fieldsCiscoDiscovery = []string{
	fieldTimestamp,
	fieldVersion,  // int32
	fieldTTL,      // int32
	fieldChecksum, // int32
	fieldValues,   // []*CiscoDiscoveryValue
}

// CSVHeader returns the CSV header for the audit record.
func (cd *CiscoDiscovery) CSVHeader() []string {
	return filter(fieldsCiscoDiscovery)
}

// CSVRecord returns the CSV record for the audit record.
func (cd *CiscoDiscovery) CSVRecord() []string {
	values := make([]string, len(cd.Values))

	for i, v := range cd.Values {
		values[i] = v.toString()
	}

	return filter([]string{
		formatTimestamp(cd.Timestamp),
		formatInt32(cd.Version),  // int32
		formatInt32(cd.TTL),      // int32
		formatInt32(cd.Checksum), // int32
		join(values...),          // []*CiscoDiscoveryValue
	})
}

// Time returns the timestamp associated with the audit record.
func (cd *CiscoDiscovery) Time() int64 {
	return cd.Timestamp
}

func (v CiscoDiscoveryValue) toString() string {
	var b strings.Builder

	b.WriteString(StructureBegin)
	b.WriteString(formatInt32(v.Type))
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(v.Length))
	b.WriteString(FieldSeparator)
	b.WriteString(hex.EncodeToString(v.Value))
	b.WriteString(StructureEnd)

	return b.String()
}

// JSON returns the JSON representation of the audit record.
func (cd *CiscoDiscovery) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	cd.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(cd)
}

var ciscoDiscoveryMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_CiscoDiscovery.String()),
		Help: Type_NC_CiscoDiscovery.String() + " audit records",
	},
	fieldsCiscoDiscovery[1:],
)

// Inc increments the metrics for the audit record.
func (cd *CiscoDiscovery) Inc() {
	ciscoDiscoveryMetric.WithLabelValues(cd.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (cd *CiscoDiscovery) SetPacketContext(*PacketContext) {}

// Src TODO.
// Src returns the source address of the audit record.
func (cd *CiscoDiscovery) Src() string {
	return ""
}

// Dst returns the destination address of the audit record.
func (cd *CiscoDiscovery) Dst() string {
	return ""
}

var ciscoDiscoveryEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (cd *CiscoDiscovery) Encode() []string {
	return filter([]string{
		ciscoDiscoveryEncoder.Int64(fieldTimestamp, cd.Timestamp),
		ciscoDiscoveryEncoder.Int32(fieldVersion, cd.Version),   // int32
		ciscoDiscoveryEncoder.Int32(fieldTTL, cd.TTL),           // int32
		ciscoDiscoveryEncoder.Int32(fieldChecksum, cd.Checksum), // int32

		// TODO: flatten
		//join(values...),          // []*CiscoDiscoveryValue
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (cd *CiscoDiscovery) Analyze() {
}

// NetcapType returns the type of the current audit record
func (cd *CiscoDiscovery) NetcapType() Type {
	return Type_NC_CiscoDiscovery
}
