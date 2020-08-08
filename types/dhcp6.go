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
	"encoding/hex"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

var fieldsDHCPv6 = []string{
	"Timestamp",     // string
	"MsgType",       // int32
	"HopCount",      // int32
	"LinkAddr",      // string
	"PeerAddr",      // string
	"TransactionID", // []byte
	"Options",       // []*DHCPv6Option
	"SrcIP",
	"DstIP",
	"SrcPort",
	"DstPort",
}

// CSVHeader returns the CSV header for the audit record.
func (d *DHCPv6) CSVHeader() []string {
	return filter(fieldsDHCPv6)
}

// CSVRecord returns the CSV record for the audit record.
func (d *DHCPv6) CSVRecord() []string {
	var opts []string
	for _, o := range d.Options {
		opts = append(opts, o.toString())
	}
	// prevent accessing nil pointer
	if d.Context == nil {
		d.Context = &PacketContext{}
	}
	return filter([]string{
		formatTimestamp(d.Timestamp),        // string
		formatInt32(d.MsgType),              // int32
		formatInt32(d.HopCount),             // int32
		d.LinkAddr,                          // string
		d.PeerAddr,                          // string
		hex.EncodeToString(d.TransactionID), // []byte
		strings.Join(opts, ""),              // []*DHCPv6Option
		d.Context.SrcIP,
		d.Context.DstIP,
		d.Context.SrcPort,
		d.Context.DstPort,
	})
}

// Time returns the timestamp associated with the audit record.
func (d *DHCPv6) Time() string {
	return d.Timestamp
}

func (d DHCPv6Option) toString() string {
	var b strings.Builder
	b.WriteString(Begin)
	b.WriteString(formatInt32(d.Code))
	b.WriteString(Separator)
	b.WriteString(formatInt32(d.Length))
	b.WriteString(Separator)
	b.WriteString(hex.EncodeToString(d.Data))
	b.WriteString(End)
	return b.String()
}

// JSON returns the JSON representation of the audit record.
func (d *DHCPv6) JSON() (string, error) {
	return jsonMarshaler.MarshalToString(d)
}

var dhcp6Metric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_DHCPv6.String()),
		Help: Type_NC_DHCPv6.String() + " audit records",
	},
	fieldsDHCPv6[1:],
)

// Inc increments the metrics for the audit record.
func (d *DHCPv6) Inc() {
	dhcp6Metric.WithLabelValues(d.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (d *DHCPv6) SetPacketContext(ctx *PacketContext) {
	d.Context = ctx
}

// Src returns the source address of the audit record.
func (d *DHCPv6) Src() string {
	if d.Context != nil {
		return d.Context.SrcIP
	}
	return ""
}

// Dst returns the destination address of the audit record.
func (d *DHCPv6) Dst() string {
	if d.Context != nil {
		return d.Context.DstIP
	}
	return ""
}
