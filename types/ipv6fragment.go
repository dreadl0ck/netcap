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
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	fieldReserved1      = "Reserved1"
	fieldFragmentOffset = "FragmentOffset"
	fieldReserved2      = "Reserved2"
	fieldMoreFragments  = "MoreFragments"
	fieldIdentification = "Identification"
)

var fieldsIPv6Fragment = []string{
	fieldTimestamp,
	fieldNextHeader,
	fieldReserved1,
	fieldFragmentOffset,
	fieldReserved2,
	fieldMoreFragments,
	fieldIdentification,
	fieldSrcIP,
	fieldDstIP,
	fieldSrcPort,
	fieldDstPort,
}

// CSVHeader returns the CSV header for the audit record.
func (a *IPv6Fragment) CSVHeader() []string {
	return filter(fieldsIPv6Fragment)
}

// CSVRecord returns the CSV record for the audit record.
func (a *IPv6Fragment) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(a.Timestamp),
		formatInt32(a.NextHeader),           // int32
		formatInt32(a.Reserved1),            // int32
		formatInt32(a.FragmentOffset),       // int32
		formatInt32(a.Reserved2),            // int32
		strconv.FormatBool(a.MoreFragments), // bool
		formatUint32(a.Identification),      // uint32
		a.SrcIP,
		a.DstIP,
		formatInt32(a.SrcPort),
		formatInt32(a.DstPort),
	})
}

// Time returns the timestamp associated with the audit record.
func (a *IPv6Fragment) Time() int64 {
	return a.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (a *IPv6Fragment) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	a.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(a)
}

var ipv6fragMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_IPv6Fragment.String()),
		Help: Type_NC_IPv6Fragment.String() + " audit records",
	},
	fieldsIPv6Fragment[1:],
)

// Inc increments the metrics for the audit record.
func (a *IPv6Fragment) Inc() {
	ipv6fragMetric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (a *IPv6Fragment) SetPacketContext(ctx *PacketContext) {
	a.SrcIP = ctx.SrcIP
	a.DstIP = ctx.DstIP
	a.SrcPort = ctx.SrcPort
	a.DstPort = ctx.DstPort
}

// Src returns the source address of the audit record.
func (a *IPv6Fragment) Src() string {
	return a.SrcIP
}

// Dst returns the destination address of the audit record.
func (a *IPv6Fragment) Dst() string {
	return a.DstIP
}

var ipv6fragmentEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (a *IPv6Fragment) Encode() []string {
	return filter([]string{
		ipv6fragmentEncoder.Int64(fieldTimestamp, a.Timestamp),
		ipv6fragmentEncoder.Int32(fieldNextHeader, a.NextHeader),          // int32
		ipv6fragmentEncoder.Int32(fieldReserved1, a.Reserved1),            // int32
		ipv6fragmentEncoder.Int32(fieldFragmentOffset, a.FragmentOffset),  // int32
		ipv6fragmentEncoder.Int32(fieldReserved2, a.Reserved2),            // int32
		ipv6fragmentEncoder.Bool(a.MoreFragments),                         // bool
		ipv6fragmentEncoder.Uint32(fieldIdentification, a.Identification), // uint32
		ipv6fragmentEncoder.String(fieldSrcIP, a.SrcIP),
		ipv6fragmentEncoder.String(fieldDstIP, a.DstIP),
		ipv6fragmentEncoder.Int32(fieldSrcPort, a.SrcPort),
		ipv6fragmentEncoder.Int32(fieldDstPort, a.DstPort),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (a *IPv6Fragment) Analyze() {}

// NetcapType returns the type of the current audit record
func (a *IPv6Fragment) NetcapType() Type {
	return Type_NC_IPv6Fragment
}
