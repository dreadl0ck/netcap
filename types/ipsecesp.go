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
	"github.com/dreadl0ck/netcap/encoder"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const fieldLenEncrypted = "Encrypted"

var fieldsIPSecESP = []string{
	fieldTimestamp,
	fieldSPI,
	fieldSeq,
	fieldLenEncrypted,
	fieldSrcIP, // string
	fieldDstIP, // string
}

// CSVHeader returns the CSV header for the audit record.
func (a *IPSecESP) CSVHeader() []string {
	return filter(fieldsIPSecESP)
}

// CSVRecord returns the CSV record for the audit record.
func (a *IPSecESP) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(a.Timestamp),
		formatInt32(a.SPI),
		formatInt32(a.Seq),
		formatInt32(a.LenEncrypted),
		a.SrcIP,
		a.DstIP,
	})
}

// Time returns the timestamp associated with the audit record.
func (a *IPSecESP) Time() int64 {
	return a.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (a *IPSecESP) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	a.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(a)
}

var ipSecEspMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_IPSecESP.String()),
		Help: Type_NC_IPSecESP.String() + " audit records",
	},
	fieldsIPSecESP[1:],
)

// Inc increments the metrics for the audit record.
func (a *IPSecESP) Inc() {
	ipSecEspMetric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (a *IPSecESP) SetPacketContext(ctx *PacketContext) {
	a.SrcIP = ctx.SrcIP
	a.DstIP = ctx.DstIP
}

// Src returns the source address of the audit record.
func (a *IPSecESP) Src() string {
	return a.SrcIP
}

// Dst returns the destination address of the audit record.
func (a *IPSecESP) Dst() string {
	return a.DstIP
}

var ipsecespEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (a *IPSecESP) Encode() []string {
	return filter([]string{
		ipsecespEncoder.Int64(fieldTimestamp, a.Timestamp),
		ipsecespEncoder.Int32(fieldSPI, a.SPI),
		ipsecespEncoder.Int32(fieldSeq, a.Seq),
		ipsecespEncoder.Int32(fieldLenEncrypted, a.LenEncrypted),
		ipsecespEncoder.String(fieldSrcIP, a.SrcIP),
		ipsecespEncoder.String(fieldDstIP, a.DstIP),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (a *IPSecESP) Analyze() {}

// NetcapType returns the type of the current audit record
func (a *IPSecESP) NetcapType() Type {
	return Type_NC_IPSecESP
}
