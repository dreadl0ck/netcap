/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package types

import (
	"encoding/hex"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/encoder"

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
