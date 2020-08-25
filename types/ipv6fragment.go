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
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

var fieldsIPv6Fragment = []string{
	"Timestamp",
	"NextHeader",
	"Reserved1",
	"FragmentOffset",
	"Reserved2",
	"MoreFragments",
	"Identification",
	"SrcIP",
	"DstIP",
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
	//	// a.Timestamp = utils.TimeToUnixMilli(a.Timestamp)
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
