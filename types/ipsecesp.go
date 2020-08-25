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
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

var fieldsIPSecESP = []string{
	"Timestamp",
	"SPI",
	"Seq",
	"LenEncrypted",
	"SrcIP", // string
	"DstIP", // string
}

// CSVHeader returns the CSV header for the audit record.
func (a *IPSecESP) CSVHeader() []string {
	return filter(fieldsIPSecESP)
}

// CSVRecord returns the CSV record for the audit record.
func (a *IPSecESP) CSVRecord() []string {
	// prevent accessing nil pointer
	if a.Context == nil {
		a.Context = &PacketContext{}
	}
	return filter([]string{
		formatTimestamp(a.Timestamp),
		formatInt32(a.SPI),
		formatInt32(a.Seq),
		formatInt32(a.LenEncrypted),
		a.Context.SrcIP,
		a.Context.DstIP,
	})
}

// Time returns the timestamp associated with the audit record.
func (a *IPSecESP) Time() int64 {
	return a.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (a *IPSecESP) JSON() (string, error) {
	//	// a.Timestamp = utils.TimeToUnixMilli(a.Timestamp)
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
	a.Context = ctx
}

// Src returns the source address of the audit record.
func (a *IPSecESP) Src() string {
	if a.Context != nil {
		return a.Context.SrcIP
	}
	return ""
}

// Dst returns the destination address of the audit record.
func (a *IPSecESP) Dst() string {
	if a.Context != nil {
		return a.Context.DstIP
	}
	return ""
}
