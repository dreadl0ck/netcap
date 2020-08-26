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
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var fieldsICMPv6NeighborAdvertisement = []string{
	"Timestamp",
	"Flags",         // int32
	"TargetAddress", // string
	"Options",       // []*ICMPv6Option
	"SrcIP",
	"DstIP",
}

// CSVHeader returns the CSV header for the audit record.
func (i *ICMPv6NeighborAdvertisement) CSVHeader() []string {
	return filter(fieldsICMPv6NeighborAdvertisement)
}

// CSVRecord returns the CSV record for the audit record.
func (i *ICMPv6NeighborAdvertisement) CSVRecord() []string {
	var opts []string
	for _, o := range i.Options {
		opts = append(opts, o.toString())
	}

	return filter([]string{
		formatTimestamp(i.Timestamp),
		formatInt32(i.Flags),
		i.TargetAddress,
		strings.Join(opts, ""),
		i.SrcIP,
		i.DstIP,
	})
}

// Time returns the timestamp associated with the audit record.
func (i *ICMPv6NeighborAdvertisement) Time() int64 {
	return i.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (i *ICMPv6NeighborAdvertisement) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	i.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(i)
}

var icmp6naMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_ICMPv6NeighborAdvertisement.String()),
		Help: Type_NC_ICMPv6NeighborAdvertisement.String() + " audit records",
	},
	fieldsICMPv6NeighborAdvertisement[1:],
)

// Inc increments the metrics for the audit record.
func (i *ICMPv6NeighborAdvertisement) Inc() {
	icmp6naMetric.WithLabelValues(i.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (i *ICMPv6NeighborAdvertisement) SetPacketContext(ctx *PacketContext) {
	i.SrcIP = ctx.SrcIP
	i.DstIP = ctx.DstIP
}

// Src returns the source address of the audit record.
func (i *ICMPv6NeighborAdvertisement) Src() string {
	return i.SrcIP
}

// Dst returns the destination address of the audit record.
func (i *ICMPv6NeighborAdvertisement) Dst() string {
	return i.DstIP
}
