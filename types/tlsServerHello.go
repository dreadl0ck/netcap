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
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var fieldsTLSServerHello = []string{
	"Timestamp",
	"Version",
	"Random",
	"SessionID",
	"CipherSuite",
	"CompressionMethod",
	"NextProtoNeg",
	"NextProtos",
	"OCSPStapling",
	"TicketSupported",
	"SecureRenegotiationSupported",
	"SecureRenegotiation",
	"AlpnProtocol",
	"Ems",
	"SupportedVersion",
	"SelectedIdentityPresent",
	"SelectedIdentity",
	"Cookie",
	"SelectedGroup",
	"Extensions",
	"SrcIP",
	"DstIP",
	"SrcMAC",
	"DstMAC",
	"SrcPort",
	"DstPort",
	"Ja3S",
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
		hex.EncodeToString(t.Random),
		hex.EncodeToString(t.SessionID),
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
