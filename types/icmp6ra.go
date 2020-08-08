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

var fieldsICMPv6RouterAdvertisement = []string{
	"Timestamp",
	"HopLimit",       //  int32
	"Flags",          //  int32
	"RouterLifetime", //  int32
	"ReachableTime",  //  uint32
	"RetransTimer",   //  uint32
	"Options",        //  []*ICMPv6Option
	"SrcIP",
	"DstIP",
}

// CSVHeader returns the CSV header for the audit record.
func (i *ICMPv6RouterAdvertisement) CSVHeader() []string {
	return filter(fieldsICMPv6RouterAdvertisement)
}

// CSVRecord returns the CSV record for the audit record.
func (i *ICMPv6RouterAdvertisement) CSVRecord() []string {
	var opts []string
	for _, o := range i.Options {
		opts = append(opts, o.ToString())
	}
	// prevent accessing nil pointer
	if i.Context == nil {
		i.Context = &PacketContext{}
	}
	return filter([]string{
		formatTimestamp(i.Timestamp),
		formatInt32(i.HopLimit),       // int32
		formatInt32(i.Flags),          // int32
		formatInt32(i.RouterLifetime), // int32
		formatUint32(i.ReachableTime), // uint32
		formatUint32(i.RetransTimer),  // uint32
		strings.Join(opts, ""),
		i.Context.SrcIP,
		i.Context.DstIP,
	})
}

// Time returns the timestamp associated with the audit record.
func (i *ICMPv6RouterAdvertisement) Time() string {
	return i.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (i *ICMPv6RouterAdvertisement) JSON() (string, error) {
	return jsonMarshaler.MarshalToString(i)
}

var icmp6raMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_ICMPv6RouterAdvertisement.String()),
		Help: Type_NC_ICMPv6RouterAdvertisement.String() + " audit records",
	},
	fieldsICMPv6RouterAdvertisement[1:],
)

func init() {
	prometheus.MustRegister(icmp6raMetric)
}

// Inc increments the metrics for the audit record.
func (i *ICMPv6RouterAdvertisement) Inc() {
	icmp6raMetric.WithLabelValues(i.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (i *ICMPv6RouterAdvertisement) SetPacketContext(ctx *PacketContext) {
	i.Context = ctx
}

// Src returns the source address of the audit record.
func (i *ICMPv6RouterAdvertisement) Src() string {
	if i.Context != nil {
		return i.Context.SrcIP
	}
	return ""
}

// Dst returns the destination address of the audit record.
func (i *ICMPv6RouterAdvertisement) Dst() string {
	if i.Context != nil {
		return i.Context.DstIP
	}
	return ""
}
