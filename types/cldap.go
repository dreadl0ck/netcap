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
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/encoder"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	fieldBaseObject = "BaseObject"
	fieldFilter     = "Filter"
	fieldDomainName = "DomainName"
	fieldForestName = "ForestName"
	fieldDCSiteName = "DCSiteName"
)

var fieldsCLDAP = []string{
	fieldTimestamp,
	fieldMessageID,  // int32
	fieldOperation,  // string
	fieldBaseObject, // string
	fieldFilter,     // string
	fieldAttributes, // []string
	fieldDomainName, // string
	fieldForestName, // string
	fieldDCSiteName, // string
	fieldSrcIP,
	fieldDstIP,
	fieldSrcPort, // int32
	fieldDstPort, // int32
}

// CSVHeader returns the CSV header for the audit record.
func (a *CLDAP) CSVHeader() []string {
	return filter(fieldsCLDAP)
}

// CSVRecord returns the CSV record for the audit record.
func (a *CLDAP) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(a.Timestamp),
		formatInt32(a.MessageID), // int32
		a.Operation,              // string
		a.BaseObject,             // string
		a.Filter,                 // string
		join(a.Attributes...),    // []string
		a.DomainName,             // string
		a.ForestName,             // string
		a.DCSiteName,             // string
		a.SrcIP,
		a.DstIP,
		formatInt32(a.SrcPort), // int32
		formatInt32(a.DstPort), // int32
	})
}

// Time returns the timestamp associated with the audit record.
func (a *CLDAP) Time() int64 {
	return a.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (a *CLDAP) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	a.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(a)
}

var cldapMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_CLDAP.String()),
		Help: Type_NC_CLDAP.String() + " audit records",
	},
	fieldsCLDAP[1:],
)

// Inc increments the metrics for the audit record.
func (a *CLDAP) Inc() {
	cldapMetric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (a *CLDAP) SetPacketContext(ctx *PacketContext) {
	a.SrcIP = ctx.SrcIP
	a.DstIP = ctx.DstIP
}

// Src returns the source address of the audit record.
func (a *CLDAP) Src() string {
	return a.SrcIP
}

// Dst returns the destination address of the audit record.
func (a *CLDAP) Dst() string {
	return a.DstIP
}

var cldapEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (a *CLDAP) Encode() []string {
	return filter([]string{
		cldapEncoder.Int64(fieldTimestamp, a.Timestamp),
		cldapEncoder.Int32(fieldMessageID, a.MessageID),             // int32
		cldapEncoder.String(fieldOperation, a.Operation),            // string
		cldapEncoder.String(fieldBaseObject, a.BaseObject),          // string
		cldapEncoder.String(fieldFilter, a.Filter),                  // string
		cldapEncoder.String(fieldAttributes, join(a.Attributes...)), // []string
		cldapEncoder.String(fieldDomainName, a.DomainName),          // string
		cldapEncoder.String(fieldForestName, a.ForestName),          // string
		cldapEncoder.String(fieldDCSiteName, a.DCSiteName),          // string
		cldapEncoder.String(fieldSrcIP, a.SrcIP),
		cldapEncoder.String(fieldDstIP, a.DstIP),
		cldapEncoder.Int32(fieldSrcPort, a.SrcPort), // int32
		cldapEncoder.Int32(fieldDstPort, a.DstPort), // int32
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (a *CLDAP) Analyze() {
}

// NetcapType returns the type of the current audit record
func (a *CLDAP) NetcapType() Type {
	return Type_NC_CLDAP
}
