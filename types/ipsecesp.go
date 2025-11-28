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
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/encoder"

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
