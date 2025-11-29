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
	fieldIEC62351UnderlyingProtocol     = "UnderlyingProtocol"
	fieldIEC62351SecurityVersion        = "SecurityVersion"
	fieldIEC62351MessageType            = "MessageType"
	fieldIEC62351MessageTypeName        = "MessageTypeName"
	fieldIEC62351IsRequest              = "IsRequest"
	fieldIEC62351AuthenticationMechanism = "AuthenticationMechanism"
	fieldIEC62351UserIdentity           = "UserIdentity"
	fieldIEC62351CertificateSubject     = "CertificateSubject"
	fieldIEC62351CertificateValid       = "CertificateValid"
	fieldIEC62351SessionId              = "SessionId"
	fieldIEC62351SecurityPolicy         = "SecurityPolicy"
	fieldIEC62351CipherSuite            = "CipherSuite"
	fieldIEC62351TLSVersion             = "TLSVersion"
	fieldIEC62351MutualAuthentication   = "MutualAuthentication"
	fieldIEC62351Role                   = "Role"
	fieldIEC62351Permission             = "Permission"
	fieldIEC62351AccessGranted          = "AccessGranted"
	fieldIEC62351AuditEventType         = "AuditEventType"
	fieldIEC62351AuditEventOutcome      = "AuditEventOutcome"
	fieldIEC62351MACValid               = "MACValid"
	fieldIEC62351ErrorMessage           = "ErrorMessage"
	fieldIEC62351IsSecurityRelevant     = "IsSecurityRelevant"
	fieldIEC62351IsCriticalOperation    = "IsCriticalOperation"
	fieldIEC62351IsAuthenticationEvent  = "IsAuthenticationEvent"
	fieldIEC62351IsAuthorizationEvent   = "IsAuthorizationEvent"
	fieldIEC62351IsSecurityAlert        = "IsSecurityAlert"
	fieldIEC62351SignatureValid         = "SignatureValid"
)

var fieldsIEC62351 = []string{
	fieldTimestamp,
	fieldSrcIP,
	fieldDstIP,
	fieldSrcPort,
	fieldDstPort,
	fieldIEC62351UnderlyingProtocol,
	fieldIEC62351SecurityVersion,
	fieldIEC62351MessageType,
	fieldIEC62351MessageTypeName,
	fieldIEC62351IsRequest,
	fieldIEC62351AuthenticationMechanism,
	fieldIEC62351UserIdentity,
	fieldIEC62351CertificateSubject,
	fieldIEC62351CertificateValid,
	fieldIEC62351SessionId,
	fieldIEC62351SecurityPolicy,
	fieldIEC62351CipherSuite,
	fieldIEC62351TLSVersion,
	fieldIEC62351MutualAuthentication,
	fieldIEC62351Role,
	fieldIEC62351Permission,
	fieldIEC62351AccessGranted,
	fieldIEC62351AuditEventType,
	fieldIEC62351AuditEventOutcome,
	fieldIEC62351MACValid,
	fieldErrorCode,
	fieldIEC62351ErrorMessage,
	fieldIEC62351IsSecurityRelevant,
	fieldIEC62351IsCriticalOperation,
	fieldIEC62351IsAuthenticationEvent,
	fieldIEC62351IsAuthorizationEvent,
	fieldIEC62351IsSecurityAlert,
	fieldIEC62351SignatureValid,
}

// CSVHeader returns the CSV header for the audit record.
func (i *IEC62351) CSVHeader() []string {
	return filter(fieldsIEC62351)
}

// CSVRecord returns the CSV record for the audit record.
func (i *IEC62351) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(i.Timestamp),
		i.SrcIP,
		i.DstIP,
		formatInt32(i.SrcPort),
		formatInt32(i.DstPort),
		i.UnderlyingProtocol,
		formatInt32(i.SecurityVersion),
		formatInt32(i.MessageType),
		i.MessageTypeName,
		strconv.FormatBool(i.IsRequest),
		i.AuthenticationMechanism,
		i.UserIdentity,
		i.CertificateSubject,
		strconv.FormatBool(i.CertificateValid),
		i.SessionId,
		i.SecurityPolicy,
		i.CipherSuite,
		i.TLSVersion,
		strconv.FormatBool(i.MutualAuthentication),
		i.Role,
		i.Permission,
		strconv.FormatBool(i.AccessGranted),
		i.AuditEventType,
		i.AuditEventOutcome,
		strconv.FormatBool(i.MACValid),
		formatInt32(i.ErrorCode),
		i.ErrorMessage,
		strconv.FormatBool(i.IsSecurityRelevant),
		strconv.FormatBool(i.IsCriticalOperation),
		strconv.FormatBool(i.IsAuthenticationEvent),
		strconv.FormatBool(i.IsAuthorizationEvent),
		strconv.FormatBool(i.IsSecurityAlert),
		strconv.FormatBool(i.SignatureValid),
	})
}

// Time returns the timestamp associated with the audit record.
func (i *IEC62351) Time() int64 {
	return i.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (i *IEC62351) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	i.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(i)
}

var iec62351Metric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_IEC62351.String()),
		Help: Type_NC_IEC62351.String() + " audit records",
	},
	fieldsIEC62351[1:],
)

// Inc increments the metrics for the audit record.
func (i *IEC62351) Inc() {
	iec62351Metric.WithLabelValues(i.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (i *IEC62351) SetPacketContext(ctx *PacketContext) {
	i.SrcIP = ctx.SrcIP
	i.DstIP = ctx.DstIP
	i.SrcPort = ctx.SrcPort
	i.DstPort = ctx.DstPort
}

// Src returns the source address of the audit record.
func (i *IEC62351) Src() string {
	return i.SrcIP
}

// Dst returns the destination address of the audit record.
func (i *IEC62351) Dst() string {
	return i.DstIP
}

var iec62351Encoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration.
func (i *IEC62351) Encode() []string {
	return filter([]string{
		iec62351Encoder.Int64(fieldTimestamp, i.Timestamp),
		iec62351Encoder.String(fieldSrcIP, i.SrcIP),
		iec62351Encoder.String(fieldDstIP, i.DstIP),
		iec62351Encoder.Int32(fieldSrcPort, i.SrcPort),
		iec62351Encoder.Int32(fieldDstPort, i.DstPort),
		iec62351Encoder.String(fieldIEC62351UnderlyingProtocol, i.UnderlyingProtocol),
		iec62351Encoder.Int32(fieldIEC62351SecurityVersion, i.SecurityVersion),
		iec62351Encoder.Int32(fieldIEC62351MessageType, i.MessageType),
		iec62351Encoder.String(fieldIEC62351MessageTypeName, i.MessageTypeName),
		iec62351Encoder.Bool(i.IsRequest),
		iec62351Encoder.String(fieldIEC62351AuthenticationMechanism, i.AuthenticationMechanism),
		iec62351Encoder.String(fieldIEC62351UserIdentity, i.UserIdentity),
		iec62351Encoder.String(fieldIEC62351CertificateSubject, i.CertificateSubject),
		iec62351Encoder.Bool(i.CertificateValid),
		iec62351Encoder.String(fieldIEC62351SessionId, i.SessionId),
		iec62351Encoder.String(fieldIEC62351SecurityPolicy, i.SecurityPolicy),
		iec62351Encoder.String(fieldIEC62351CipherSuite, i.CipherSuite),
		iec62351Encoder.String(fieldIEC62351TLSVersion, i.TLSVersion),
		iec62351Encoder.Bool(i.MutualAuthentication),
		iec62351Encoder.String(fieldIEC62351Role, i.Role),
		iec62351Encoder.String(fieldIEC62351Permission, i.Permission),
		iec62351Encoder.Bool(i.AccessGranted),
		iec62351Encoder.String(fieldIEC62351AuditEventType, i.AuditEventType),
		iec62351Encoder.String(fieldIEC62351AuditEventOutcome, i.AuditEventOutcome),
		iec62351Encoder.Bool(i.MACValid),
		iec62351Encoder.Int32(fieldErrorCode, i.ErrorCode),
		iec62351Encoder.String(fieldIEC62351ErrorMessage, i.ErrorMessage),
		iec62351Encoder.Bool(i.IsSecurityRelevant),
		iec62351Encoder.Bool(i.IsCriticalOperation),
		iec62351Encoder.Bool(i.IsAuthenticationEvent),
		iec62351Encoder.Bool(i.IsAuthorizationEvent),
		iec62351Encoder.Bool(i.IsSecurityAlert),
		iec62351Encoder.Bool(i.SignatureValid),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (i *IEC62351) Analyze() {}

// NetcapType returns the type of the current audit record.
func (i *IEC62351) NetcapType() Type {
	return Type_NC_IEC62351
}

