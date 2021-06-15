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
	fieldHandshakeType    = "HandshakeType"
	fieldHandshakeLen     = "HandshakeLen"
	fieldHandshakeVersion = "HandshakeVersion"
	fieldSessionIDLen     = "SessionIDLen"
	fieldSessionID        = "SessionID"
	fieldCipherSuiteLen   = "CipherSuiteLen"
	fieldExtensionLen     = "ExtensionLen"
	fieldSNI              = "SNI"
	fieldOSCP             = "OSCP"
	fieldCipherSuites     = "CipherSuites"
	fieldCompressMethods  = "CompressMethods"
	fieldSignatureAlgs    = "SignatureAlgs"
	fieldSupportedGroups  = "SupportedGroups"
	fieldSupportedPoints  = "SupportedPoints"
	fieldALPNs            = "ALPNs"
)

var fieldsTLSClientHello = []string{
	fieldTimestamp,
	fieldType,
	fieldVersion,
	fieldMessageLen,
	fieldHandshakeType,
	fieldHandshakeLen,
	fieldHandshakeVersion,
	fieldSessionIDLen,
	fieldCipherSuiteLen,
	fieldExtensionLen,
	fieldSNI,
	fieldOSCP,
	fieldCipherSuites,
	fieldCompressMethods,
	fieldSignatureAlgs,
	fieldSupportedGroups,
	fieldSupportedPoints,
	fieldALPNs,
	fieldJa3,
	fieldSrcIP,
	fieldDstIP,
	fieldSrcMAC,
	fieldDstMAC,
	fieldSrcPort,
	fieldDstPort,
}

// CSVHeader returns the CSV header for the audit record.
func (t *TLSClientHello) CSVHeader() []string {
	return filter(fieldsTLSClientHello)
}

// CSVRecord returns the CSV record for the audit record.
func (t *TLSClientHello) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(t.Timestamp),
		formatInt32(t.Type),
		formatInt32(t.Version),
		formatInt32(t.MessageLen),
		formatInt32(t.HandshakeType),
		strconv.FormatUint(uint64(t.HandshakeLen), 10),
		formatInt32(t.HandshakeVersion),
		hex.EncodeToString(t.Random),
		strconv.FormatUint(uint64(t.SessionIDLen), 10),
		hex.EncodeToString(t.SessionID),
		formatInt32(t.CipherSuiteLen),
		formatInt32(t.ExtensionLen),
		t.SNI,
		strconv.FormatBool(t.OSCP),
		joinInts(t.CipherSuites),
		joinInts(t.CompressMethods),
		joinInts(t.SignatureAlgs),
		joinInts(t.SupportedGroups),
		joinInts(t.SupportedPoints),
		join(t.ALPNs...),
		t.Ja3,
		t.SrcIP,
		t.DstIP,
		t.SrcMAC,
		t.DstMAC,
		formatInt32(t.SrcPort),
		formatInt32(t.DstPort),
	})
}

// Time returns the timestamp associated with the audit record.
func (t *TLSClientHello) Time() int64 {
	return t.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (t *TLSClientHello) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	t.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(t)
}

var tlsClientMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_TLSClientHello.String()),
		Help: Type_NC_TLSClientHello.String() + " audit records",
	},
	fieldsTLSClientHello[1:],
)

// Inc increments the metrics for the audit record.
func (t *TLSClientHello) Inc() {
	tlsClientMetric.WithLabelValues(t.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (t *TLSClientHello) SetPacketContext(*PacketContext) {
}

// Src returns the source address of the audit record.
func (t *TLSClientHello) Src() string {
	return t.SrcIP
}

// Dst returns the destination address of the audit record.
func (t *TLSClientHello) Dst() string {
	return t.DstIP
}

var tlsClientHelloEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (t *TLSClientHello) Encode() []string {
	return filter([]string{
		tlsClientHelloEncoder.Int64(fieldTimestamp, t.Timestamp),
		tlsClientHelloEncoder.Int32(fieldType, t.Type),
		tlsClientHelloEncoder.Int32(fieldVersion, t.Version),
		tlsClientHelloEncoder.Int32(fieldMessageLen, t.MessageLen),
		tlsClientHelloEncoder.Int32(fieldHandshakeType, t.HandshakeType),
		tlsClientHelloEncoder.Uint32(fieldHandshakeLen, t.HandshakeLen),
		tlsClientHelloEncoder.Int32(fieldHandshakeVersion, t.HandshakeVersion),
		tlsClientHelloEncoder.Uint32(fieldSessionIDLen, t.SessionIDLen),
		tlsClientHelloEncoder.Int32(fieldCipherSuiteLen, t.CipherSuiteLen),
		tlsClientHelloEncoder.Int32(fieldExtensionLen, t.ExtensionLen),
		tlsClientHelloEncoder.String(fieldSNI, t.SNI),
		tlsClientHelloEncoder.Bool(t.OSCP),
		tlsClientHelloEncoder.String(fieldCipherSuites, joinInts(t.CipherSuites)),
		tlsClientHelloEncoder.String(fieldCompressMethods, joinInts(t.CompressMethods)),
		tlsClientHelloEncoder.String(fieldSignatureAlgs, joinInts(t.SignatureAlgs)),
		tlsClientHelloEncoder.String(fieldSupportedGroups, joinInts(t.SupportedGroups)),
		tlsClientHelloEncoder.String(fieldSupportedPoints, joinInts(t.SupportedPoints)),
		tlsClientHelloEncoder.String(fieldALPNs, join(t.ALPNs...)),
		tlsClientHelloEncoder.String(fieldJa3, t.Ja3),
		tlsClientHelloEncoder.String(fieldSrcIP, t.SrcIP),
		tlsClientHelloEncoder.String(fieldDstIP, t.DstIP),
		tlsClientHelloEncoder.String(fieldSrcMAC, t.SrcMAC),
		tlsClientHelloEncoder.String(fieldDstMAC, t.DstMAC),
		tlsClientHelloEncoder.Int32(fieldSrcPort, t.SrcPort),
		tlsClientHelloEncoder.Int32(fieldDstPort, t.DstPort),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (t *TLSClientHello) Analyze() {
}

// NetcapType returns the type of the current audit record
func (t *TLSClientHello) NetcapType() Type {
	return Type_NC_TLSClientHello
}
