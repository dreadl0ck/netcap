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

const (
	fieldReserved           = "Reserved"
	fieldSPI                = "SPI"
	fieldAuthenticationData = "AuthenticationData"
)

var fieldsIPSecAH = []string{
	fieldTimestamp,
	fieldReserved,
	fieldSPI,
	fieldSeq,
	fieldSrcIP, // string
	fieldDstIP, // string
}

// CSVHeader returns the CSV header for the audit record.
func (a *IPSecAH) CSVHeader() []string {
	return filter(fieldsIPSecAH)
}

// CSVRecord returns the CSV record for the audit record.
func (a *IPSecAH) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(a.Timestamp),
		formatInt32(a.Reserved),
		formatInt32(a.SPI),
		formatInt32(a.Seq),
		a.SrcIP,
		a.DstIP,
	})
}

// Time returns the timestamp associated with the audit record.
func (a *IPSecAH) Time() int64 {
	return a.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (a *IPSecAH) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	a.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(a)
}

var ipSecAhMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_IPSecAH.String()),
		Help: Type_NC_IPSecAH.String() + " audit records",
	},
	fieldsIPSecAH[1:],
)

// Inc increments the metrics for the audit record.
func (a *IPSecAH) Inc() {
	ipSecAhMetric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (a *IPSecAH) SetPacketContext(ctx *PacketContext) {
	a.SrcIP = ctx.SrcIP
	a.DstIP = ctx.DstIP
}

// Src returns the source address of the audit record.
func (a *IPSecAH) Src() string {
	return a.SrcIP
}

// Dst returns the destination address of the audit record.
func (a *IPSecAH) Dst() string {
	return a.DstIP
}

var ipsecahEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (a *IPSecAH) Encode() []string {
	return filter([]string{
		ipsecahEncoder.Int64(fieldTimestamp, a.Timestamp),
		ipsecahEncoder.Int32(fieldReserved, a.Reserved),
		ipsecahEncoder.Int32(fieldSPI, a.SPI),
		ipsecahEncoder.Int32(fieldSeq, a.Seq),
		ipsecahEncoder.String(fieldSrcIP, a.SrcIP),
		ipsecahEncoder.String(fieldDstIP, a.DstIP),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (a *IPSecAH) Analyze() {}

// NetcapType returns the type of the current audit record
func (a *IPSecAH) NetcapType() Type {
	return Type_NC_IPSecAH
}
