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
	"strconv"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/internal/encoder"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	fieldCipherSuite                  = "CipherSuite"
	fieldCompressionMethod            = "CompressionMethod"
	fieldNextProtoNeg                 = "NextProtoNeg"
	fieldNextProtos                   = "NextProtos"
	fieldOCSPStapling                 = "OCSPStapling"
	fieldTicketSupported              = "TicketSupported"
	fieldSecureRenegotiationSupported = "SecureRenegotiationSupported"
	fieldSecureRenegotiation          = "SecureRenegotiation"
	fieldAlpnProtocol                 = "AlpnProtocol"
	fieldEms                          = "Ems"
	fieldSupportedVersion             = "SupportedVersion"
	fieldSelectedIdentityPresent      = "SelectedIdentityPresent"
	fieldSelectedIdentity             = "SelectedIdentity"
	fieldCookie                       = "Cookie"
	fieldSelectedGroup                = "SelectedGroup"
	fieldExtensions                   = "Extensions"
	fieldJa4S                         = "Ja4S"
	fieldSSLv2ConnectionID            = "SSLv2ConnectionID"
	fieldSSLv2SessionIDHit            = "SSLv2SessionIDHit"
	fieldSSLv2CertificateType         = "SSLv2CertificateType"
)

var fieldsTLSServerHello = []string{
	fieldTimestamp,
	fieldVersion,
	//fieldRandom,
	//fieldSessionID,
	fieldCipherSuite,
	fieldCompressionMethod,
	fieldNextProtoNeg,
	fieldNextProtos,
	fieldOCSPStapling,
	fieldTicketSupported,
	fieldSecureRenegotiationSupported,
	fieldSecureRenegotiation,
	fieldAlpnProtocol,
	fieldEms,
	fieldSupportedVersion,
	fieldSelectedIdentityPresent,
	fieldSelectedIdentity,
	fieldCookie,
	fieldSelectedGroup,
	fieldExtensions,
	fieldSrcIP,
	fieldDstIP,
	fieldSrcMAC,
	fieldDstMAC,
	fieldSrcPort,
	fieldDstPort,
	fieldJa4S,
	fieldHelloFormat,
	fieldSSLv2CipherSpecs,
	fieldSSLv2ConnectionID,
	fieldSSLv2SessionIDHit,
	fieldSSLv2CertificateType,
}

// CSVHeader returns the CSV header for the audit record.
func (t *TLSServerHello) CSVHeader() []string {
	return filter(fieldsTLSServerHello)
}

// CSVRecord returns the CSV record for the audit record.
func (t *TLSServerHello) CSVRecord() []string {
	return filter(t.csvRecord())
}

func (t *TLSServerHello) csvRecord() []string {
	return []string{
		formatTimestamp(t.Timestamp),
		formatInt32(t.Version),
		//hex.EncodeToString(t.Random),
		//hex.EncodeToString(t.SessionID),
		formatInt32(t.CipherSuite),
		formatInt32(t.CompressionMethod),
		strconv.FormatBool(t.NextProtoNeg),
		join(t.NextProtos...),
		strconv.FormatBool(t.OCSPStapling),
		strconv.FormatBool(t.TicketSupported),
		strconv.FormatBool(t.SecureRenegotiationSupported),
		hex.EncodeToString(t.SecureRenegotiation),
		t.AlpnProtocol,
		strconv.FormatBool(t.Ems),
		formatInt32(t.SupportedVersion),
		strconv.FormatBool(t.SelectedIdentityPresent),
		formatInt32(t.SelectedIdentity),
		hex.EncodeToString(t.Cookie),
		formatInt32(t.SelectedGroup),
		joinInts(t.Extensions),
		t.SrcIP,
		t.DstIP,
		t.SrcMAC,
		t.DstMAC,
		formatInt32(t.SrcPort),
		formatInt32(t.DstPort),
		t.Ja4S,
		t.HelloFormat,
		joinUints(t.SSLv2CipherSpecs),
		hex.EncodeToString(t.SSLv2ConnectionID),
		strconv.FormatBool(t.SSLv2SessionIDHit),
		strconv.FormatUint(uint64(t.SSLv2CertificateType), 10),
	}
}

// Time returns the timestamp associated with the audit record.
func (t *TLSServerHello) Time() int64 {
	return t.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (t *TLSServerHello) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	t.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(t)
}

var tlsServerMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_TLSServerHello.String()),
		Help: Type_NC_TLSServerHello.String() + " audit records",
	},
	fieldsTLSServerHello[1:len(fieldsTLSServerHello)-5], // Exclude SSLv2 connection-specific data.
)

// Inc increments the metrics for the audit record.
func (t *TLSServerHello) Inc() {
	values := t.csvRecord()
	tlsServerMetric.WithLabelValues(values[1 : len(values)-5]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (t *TLSServerHello) SetPacketContext(ctx *PacketContext) {
	t.CommunityID = ctx.CommunityID
}

// Src returns the source address of the audit record.
func (t *TLSServerHello) Src() string {
	return t.SrcIP
}

// Dst returns the destination address of the audit record.
func (t *TLSServerHello) Dst() string {
	return t.DstIP
}

var tlsServerHelloEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (t *TLSServerHello) Encode() []string {
	return filter([]string{
		tlsServerHelloEncoder.Int64(fieldTimestamp, t.Timestamp),
		tlsServerHelloEncoder.Int32(fieldVersion, t.Version),
		tlsServerHelloEncoder.Int32(fieldCipherSuite, t.CipherSuite),
		tlsServerHelloEncoder.Int32(fieldCompressionMethod, t.CompressionMethod),
		tlsServerHelloEncoder.Bool(t.NextProtoNeg),
		tlsServerHelloEncoder.String(fieldNextProtos, join(t.NextProtos...)),
		tlsServerHelloEncoder.Bool(t.OCSPStapling),
		tlsServerHelloEncoder.Bool(t.TicketSupported),
		tlsServerHelloEncoder.Bool(t.SecureRenegotiationSupported),
		tlsServerHelloEncoder.String(fieldSecureRenegotiation, hex.EncodeToString(t.SecureRenegotiation)),
		tlsServerHelloEncoder.String(fieldAlpnProtocol, t.AlpnProtocol),
		tlsServerHelloEncoder.Bool(t.Ems),
		tlsServerHelloEncoder.Int32(fieldSupportedVersion, t.SupportedVersion),
		tlsServerHelloEncoder.Bool(t.SelectedIdentityPresent),
		tlsServerHelloEncoder.Int32(fieldSelectedIdentity, t.SelectedIdentity),
		tlsServerHelloEncoder.String(fieldCookie, hex.EncodeToString(t.Cookie)),
		tlsServerHelloEncoder.Int32(fieldSelectedGroup, t.SelectedGroup),
		tlsServerHelloEncoder.String(fieldExtensions, joinInts(t.Extensions)),
		tlsServerHelloEncoder.String(fieldSrcIP, t.SrcIP),
		tlsServerHelloEncoder.String(fieldDstIP, t.DstIP),
		tlsServerHelloEncoder.String(fieldSrcMAC, t.SrcMAC),
		tlsServerHelloEncoder.String(fieldDstMAC, t.DstMAC),
		tlsServerHelloEncoder.Int32(fieldSrcPort, t.SrcPort),
		tlsServerHelloEncoder.Int32(fieldDstPort, t.DstPort),
		tlsServerHelloEncoder.String(fieldJa4S, t.Ja4S),
		tlsServerHelloEncoder.String(fieldHelloFormat, t.HelloFormat),
		tlsServerHelloEncoder.String(fieldSSLv2CipherSpecs, joinUints(t.SSLv2CipherSpecs)),
		tlsServerHelloEncoder.String(fieldSSLv2ConnectionID, hex.EncodeToString(t.SSLv2ConnectionID)),
		tlsServerHelloEncoder.Bool(t.SSLv2SessionIDHit),
		tlsServerHelloEncoder.Uint32(fieldSSLv2CertificateType, t.SSLv2CertificateType),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (t *TLSServerHello) Analyze() {
}

// NetcapType returns the type of the current audit record
func (t *TLSServerHello) NetcapType() Type {
	return Type_NC_TLSServerHello
}
