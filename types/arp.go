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
	fieldAddrType            = "AddrType"
	fieldProtocol            = "Protocol"
	fieldHwAddressSize       = "HwAddressSize"
	fieldProtocolAddressSize = "ProtocolAddressSize"
	fieldOperation           = "Operation"
	fieldSrcHwAddress        = "SrcHwAddress"
	fieldSrcProtocolAddress  = "SrcProtocolAddress"
	fieldDstHwAddress        = "DstHwAddress"
	fieldDstProtocolAddress  = "DstProtocolAddress"
)

var fieldsARP = []string{
	fieldTimestamp,
	fieldAddrType,            // int32
	fieldProtocol,            // int32
	fieldHwAddressSize,       // int32
	fieldProtocolAddressSize, // int32
	fieldOperation,           // int32
	fieldSrcHwAddress,        // []byte
	fieldSrcProtocolAddress,  // []byte
	fieldDstHwAddress,        // []byte
	fieldDstProtocolAddress,  // []byte
}

// CSVHeader returns the CSV header for the audit record.
func (a *ARP) CSVHeader() []string {
	return filter(fieldsARP)
}

// CSVRecord returns the CSV record for the audit record.
func (a *ARP) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(a.Timestamp),
		formatInt32(a.AddrType),            // int32
		formatInt32(a.Protocol),            // int32
		formatInt32(a.HwAddressSize),       // int32
		formatInt32(a.ProtocolAddressSize), // int32
		formatInt32(a.Operation),           // int32
		a.SrcHwAddress,
		a.SrcProtocolAddress,
		a.DstHwAddress,
		a.DstProtocolAddress,
	})
}

// Time returns the timestamp associated with the audit record.
func (a *ARP) Time() int64 {
	return a.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (a *ARP) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	a.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(a)
}

var arpMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_ARP.String()),
		Help: Type_NC_ARP.String() + " audit records",
	},
	fieldsARP[1:],
)

// Inc increments the metrics for the audit record.
func (a *ARP) Inc() {
	arpMetric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (a *ARP) SetPacketContext(*PacketContext) {}

// Src TODO: preserve source and destination mac adresses for ARP and return them here.
// Src returns the source address of the audit record.
func (a *ARP) Src() string {
	return ""
}

// Dst TODO: preserve source and destination mac adresses for ARP and return them here.
// Dst returns the destination address of the audit record.
func (a *ARP) Dst() string {
	return ""
}

var arpEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (arp *ARP) Encode() []string {
	return filter([]string{
		arpEncoder.Int64(fieldTimestamp, arp.Timestamp),                     // int64
		arpEncoder.Int32(fieldAddrType, arp.AddrType),                       // int32
		arpEncoder.Int32(fieldProtocol, arp.Protocol),                       // int32
		arpEncoder.Int32(fieldHwAddressSize, arp.HwAddressSize),             // int32
		arpEncoder.Int32(fieldProtocolAddressSize, arp.ProtocolAddressSize), // int32
		arpEncoder.Int32(fieldOperation, arp.Operation),                     // int32
		arpEncoder.String(fieldSrcHwAddress, arp.SrcHwAddress),              // string
		arpEncoder.String(fieldSrcProtocolAddress, arp.SrcProtocolAddress),  // string
		arpEncoder.String(fieldDstHwAddress, arp.DstHwAddress),              // string
		arpEncoder.String(fieldDstProtocolAddress, arp.DstProtocolAddress),  // string
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (arp *ARP) Analyze() {}

// NetcapType returns the type of the current audit record
func (arp *ARP) NetcapType() Type {
	return Type_NC_ARP
}
