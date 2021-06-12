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
	fieldHopLimit       = "HopLimit"
	fieldRouterLifetime = "RouterLifetime"
	fieldReachableTime  = "ReachableTime"
	fieldRetransTimer   = "RetransTimer"
)

var fieldsICMPv6RouterAdvertisement = []string{
	fieldTimestamp,
	fieldHopLimit,       //  int32
	fieldFlags,          //  int32
	fieldRouterLifetime, //  int32
	fieldReachableTime,  //  uint32
	fieldRetransTimer,   //  uint32
	fieldOptions,        //  []*ICMPv6Option
	fieldSrcIP,
	fieldDstIP,
}

// CSVHeader returns the CSV header for the audit record.
func (i *ICMPv6RouterAdvertisement) CSVHeader() []string {
	return filter(fieldsICMPv6RouterAdvertisement)
}

// CSVRecord returns the CSV record for the audit record.
func (i *ICMPv6RouterAdvertisement) CSVRecord() []string {
	var opts []string
	for _, o := range i.Options {
		opts = append(opts, o.toString())
	}

	return filter([]string{
		formatTimestamp(i.Timestamp),
		formatInt32(i.HopLimit),       // int32
		formatInt32(i.Flags),          // int32
		formatInt32(i.RouterLifetime), // int32
		formatUint32(i.ReachableTime), // uint32
		formatUint32(i.RetransTimer),  // uint32
		strings.Join(opts, ""),
		i.SrcIP,
		i.DstIP,
	})
}

// Time returns the timestamp associated with the audit record.
func (i *ICMPv6RouterAdvertisement) Time() int64 {
	return i.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (i *ICMPv6RouterAdvertisement) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	i.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(i)
}

var icmp6raMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_ICMPv6RouterAdvertisement.String()),
		Help: Type_NC_ICMPv6RouterAdvertisement.String() + " audit records",
	},
	fieldsICMPv6RouterAdvertisement[1:],
)

// Inc increments the metrics for the audit record.
func (i *ICMPv6RouterAdvertisement) Inc() {
	icmp6raMetric.WithLabelValues(i.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (i *ICMPv6RouterAdvertisement) SetPacketContext(ctx *PacketContext) {
	i.SrcIP = ctx.SrcIP
	i.DstIP = ctx.DstIP
}

// Src returns the source address of the audit record.
func (i *ICMPv6RouterAdvertisement) Src() string {
	return i.SrcIP
}

// Dst returns the destination address of the audit record.
func (i *ICMPv6RouterAdvertisement) Dst() string {
	return i.DstIP
}

var icmp6raEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (i *ICMPv6RouterAdvertisement) Encode() []string {
	var opts []string
	for _, o := range i.Options {
		opts = append(opts, o.toString())
	}
	return filter([]string{
		icmp6raEncoder.Int64(fieldTimestamp, i.Timestamp),
		icmp6raEncoder.Int32(fieldHopLimit, i.HopLimit),             // int32
		icmp6raEncoder.Int32(fieldFlags, i.Flags),                   // int32
		icmp6raEncoder.Int32(fieldRouterLifetime, i.RouterLifetime), // int32
		icmp6raEncoder.Uint32(fieldReachableTime, i.ReachableTime),  // uint32
		icmp6raEncoder.Uint32(fieldRetransTimer, i.RetransTimer),    // uint32
		icmp6raEncoder.String(fieldOptions, strings.Join(opts, "")),
		icmp6raEncoder.String(fieldSrcIP, i.SrcIP),
		icmp6raEncoder.String(fieldDstIP, i.DstIP),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (i *ICMPv6RouterAdvertisement) Analyze() {}

// NetcapType returns the type of the current audit record
func (i *ICMPv6RouterAdvertisement) NetcapType() Type {
	return Type_NC_ICMPv6RouterAdvertisement
}
