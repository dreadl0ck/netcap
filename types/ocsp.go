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
	"strconv"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/encoder"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	fieldCertSerial    = "CertSerial"
	fieldCertStatus    = "CertStatus"
	fieldIssuerNameHash = "IssuerNameHash"
	fieldIssuerKeyHash = "IssuerKeyHash"
	fieldResponderID   = "ResponderID"
	fieldProducedAt    = "ProducedAt"
	fieldThisUpdate    = "ThisUpdate"
	fieldNextUpdate    = "NextUpdate"
)

var fieldsOCSP = []string{
	fieldTimestamp,
	fieldIsResponse,    // bool
	fieldResponseStatus, // int32
	fieldCertSerial,    // string
	fieldCertStatus,    // string
	fieldIssuerNameHash, // string
	fieldIssuerKeyHash, // string
	fieldResponderID,   // string
	fieldProducedAt,    // int64
	fieldThisUpdate,    // int64
	fieldNextUpdate,    // int64
	fieldSrcIP,
	fieldDstIP,
}

// CSVHeader returns the CSV header for the audit record.
func (a *OCSP) CSVHeader() []string {
	return filter(fieldsOCSP)
}

// CSVRecord returns the CSV record for the audit record.
func (a *OCSP) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(a.Timestamp),
		strconv.FormatBool(a.IsResponse),    // bool
		formatInt32(a.ResponseStatus),        // int32
		a.CertSerial,                         // string
		a.CertStatus,                         // string
		a.IssuerNameHash,                     // string
		a.IssuerKeyHash,                      // string
		a.ResponderID,                        // string
		formatInt64(a.ProducedAt),            // int64
		formatInt64(a.ThisUpdate),            // int64
		formatInt64(a.NextUpdate),            // int64
		a.SrcIP,
		a.DstIP,
	})
}

// Time returns the timestamp associated with the audit record.
func (a *OCSP) Time() int64 {
	return a.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (a *OCSP) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	a.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(a)
}

var ocspMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_OCSP.String()),
		Help: Type_NC_OCSP.String() + " audit records",
	},
	fieldsOCSP[1:],
)

// Inc increments the metrics for the audit record.
func (a *OCSP) Inc() {
	ocspMetric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (a *OCSP) SetPacketContext(ctx *PacketContext) {
	a.SrcIP = ctx.SrcIP
	a.DstIP = ctx.DstIP
}

// Src returns the source address of the audit record.
func (a *OCSP) Src() string {
	return a.SrcIP
}

// Dst returns the destination address of the audit record.
func (a *OCSP) Dst() string {
	return a.DstIP
}

var ocspEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (a *OCSP) Encode() []string {
	return filter([]string{
		ocspEncoder.Int64(fieldTimestamp, a.Timestamp),
		ocspEncoder.String(fieldIsResponse, strconv.FormatBool(a.IsResponse)), // bool
		ocspEncoder.Int32(fieldResponseStatus, a.ResponseStatus),              // int32
		ocspEncoder.String(fieldCertSerial, a.CertSerial),                     // string
		ocspEncoder.String(fieldCertStatus, a.CertStatus),                     // string
		ocspEncoder.String(fieldIssuerNameHash, a.IssuerNameHash),             // string
		ocspEncoder.String(fieldIssuerKeyHash, a.IssuerKeyHash),               // string
		ocspEncoder.String(fieldResponderID, a.ResponderID),                   // string
		ocspEncoder.Int64(fieldProducedAt, a.ProducedAt),                      // int64
		ocspEncoder.Int64(fieldThisUpdate, a.ThisUpdate),                      // int64
		ocspEncoder.Int64(fieldNextUpdate, a.NextUpdate),                      // int64
		ocspEncoder.String(fieldSrcIP, a.SrcIP),
		ocspEncoder.String(fieldDstIP, a.DstIP),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (a *OCSP) Analyze() {
}

// NetcapType returns the type of the current audit record
func (a *OCSP) NetcapType() Type {
	return Type_NC_OCSP
}
