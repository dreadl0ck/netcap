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
	"strconv"
	"strings"

	"github.com/dreadl0ck/netcap/utils"
	"github.com/prometheus/client_golang/prometheus"
)

var fieldsTLSClientHello = []string{
	"Timestamp",
	"Type",
	"Version",
	"MessageLen",
	"HandshakeType",
	"HandshakeLen",
	"HandshakeVersion",
	"Random",
	"SessionIDLen",
	"SessionID",
	"CipherSuiteLen",
	"ExtensionLen",
	"SNI",
	"OSCP",
	"CipherSuites",
	"CompressMethods",
	"SignatureAlgs",
	"SupportedGroups",
	"SupportedPoints",
	"ALPNs",
	"Ja3",
	"SrcIP",
	"DstIP",
	"SrcMAC",
	"DstMAC",
	"SrcPort",
	"DstPort",
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
func (t *TLSClientHello) Time() string {
	return t.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (t *TLSClientHello) JSON() (string, error) {
	t.Timestamp = utils.TimeToUnixMilli(t.Timestamp)
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
