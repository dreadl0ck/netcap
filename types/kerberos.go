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
	fieldMessageTypeCode  = "MessageTypeCode"
	fieldClientName       = "ClientName"
	fieldRealm            = "Realm"
	fieldEncryptionType   = "EncryptionType"
	fieldEncryptionTypeName = "EncryptionTypeName"
	fieldErrorMessage     = "ErrorMessage"
	fieldTill             = "Till"
	fieldPADataTypes      = "PADataTypes"
)

var fieldsKerberos = []string{
	fieldTimestamp,
	fieldMessageType,       // string
	fieldMessageTypeCode,   // int32
	fieldClientName,        // string
	fieldServerName,        // string
	fieldRealm,             // string
	fieldEncryptionType,    // int32
	fieldEncryptionTypeName, // string
	fieldErrorCode,         // int32
	fieldErrorMessage,      // string
	fieldTill,              // int64
	fieldPADataTypes,       // []int32
	fieldFlow,
	fieldSrcIP,
	fieldDstIP,
	fieldSrcPort,
	fieldDstPort,
}

// CSVHeader returns the CSV header for the audit record.
func (a *Kerberos) CSVHeader() []string {
	return filter(fieldsKerberos)
}

// CSVRecord returns the CSV record for the audit record.
func (a *Kerberos) CSVRecord() []string {
	paTypes := make([]string, 0, len(a.PADataTypes))
	for _, p := range a.PADataTypes {
		paTypes = append(paTypes, formatInt32(p))
	}

	return filter([]string{
		formatTimestamp(a.Timestamp),
		a.MessageType,                    // string
		formatInt32(a.MessageTypeCode),   // int32
		a.ClientName,                     // string
		a.ServerName,                     // string
		a.Realm,                          // string
		formatInt32(a.EncryptionType),    // int32
		a.EncryptionTypeName,             // string
		formatInt32(a.ErrorCode),         // int32
		a.ErrorMessage,                   // string
		formatInt64(a.Till),              // int64
		strings.Join(paTypes, ","),       // []int32
		a.Flow,
		a.SrcIP,
		a.DstIP,
		formatInt32(a.SrcPort),
		formatInt32(a.DstPort),
	})
}

// Time returns the timestamp associated with the audit record.
func (a *Kerberos) Time() int64 {
	return a.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (a *Kerberos) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	a.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(a)
}

var kerberosMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_Kerberos.String()),
		Help: Type_NC_Kerberos.String() + " audit records",
	},
	fieldsKerberos[1:],
)

// Inc increments the metrics for the audit record.
func (a *Kerberos) Inc() {
	kerberosMetric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (a *Kerberos) SetPacketContext(_ *PacketContext) {
}

// Src returns the source address of the audit record.
func (a *Kerberos) Src() string {
	return a.SrcIP
}

// Dst returns the destination address of the audit record.
func (a *Kerberos) Dst() string {
	return a.DstIP
}

var kerberosEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (a *Kerberos) Encode() []string {
	paTypes := make([]string, 0, len(a.PADataTypes))
	for _, p := range a.PADataTypes {
		paTypes = append(paTypes, strconv.Itoa(int(p)))
	}

	return filter([]string{
		kerberosEncoder.Int64(fieldTimestamp, a.Timestamp),
		kerberosEncoder.String(fieldMessageType, a.MessageType),               // string
		kerberosEncoder.Int32(fieldMessageTypeCode, a.MessageTypeCode),        // int32
		kerberosEncoder.String(fieldClientName, a.ClientName),                 // string
		kerberosEncoder.String(fieldServerName, a.ServerName),                 // string
		kerberosEncoder.String(fieldRealm, a.Realm),                           // string
		kerberosEncoder.Int32(fieldEncryptionType, a.EncryptionType),          // int32
		kerberosEncoder.String(fieldEncryptionTypeName, a.EncryptionTypeName), // string
		kerberosEncoder.Int32(fieldErrorCode, a.ErrorCode),                    // int32
		kerberosEncoder.String(fieldErrorMessage, a.ErrorMessage),             // string
		kerberosEncoder.Int64(fieldTill, a.Till),                              // int64
		kerberosEncoder.String(fieldPADataTypes, strings.Join(paTypes, ",")),  // []int32
		kerberosEncoder.String(fieldFlow, a.Flow),
		kerberosEncoder.String(fieldSrcIP, a.SrcIP),
		kerberosEncoder.String(fieldDstIP, a.DstIP),
		kerberosEncoder.Int32(fieldSrcPort, a.SrcPort),
		kerberosEncoder.Int32(fieldDstPort, a.DstPort),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (a *Kerberos) Analyze() {
}

// NetcapType returns the type of the current audit record
func (a *Kerberos) NetcapType() Type {
	return Type_NC_Kerberos
}
