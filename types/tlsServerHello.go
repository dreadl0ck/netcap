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
	"strconv"
	"strings"
	"time"

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
	fieldJa3S                         = "Ja3S"
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
	fieldJa3S,
}

// CSVHeader returns the CSV header for the audit record.
func (t *TLSServerHello) CSVHeader() []string {
	return filter(fieldsTLSServerHello)
}

// CSVRecord returns the CSV record for the audit record.
func (t *TLSServerHello) CSVRecord() []string {
	return filter([]string{
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
		t.Ja3S,
	})
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
	fieldsTLSServerHello[1:],
)

// Inc increments the metrics for the audit record.
func (t *TLSServerHello) Inc() {
	tlsServerMetric.WithLabelValues(t.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (t *TLSServerHello) SetPacketContext(*PacketContext) {
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
		tlsServerHelloEncoder.String(fieldJa3S, t.Ja3S),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (t *TLSServerHello) Analyze() {
}

// NetcapType returns the type of the current audit record
func (t *TLSServerHello) NetcapType() Type {
	return Type_NC_TLSServerHello
}
