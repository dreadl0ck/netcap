/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
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
}

func (d DHCPv6) CSVHeader() []string {
	return filter(fieldsDHCPv6)
}

func (d DHCPv6) CSVRecord() []string {
	var opts []string
	for _, o := range d.Options {
		opts = append(opts, o.ToString())
	}
	return filter([]string{
		formatTimestamp(d.Timestamp),        // string
		formatInt32(d.MsgType),              // int32
		formatInt32(d.HopCount),             // int32
		d.LinkAddr,                          // string
		d.PeerAddr,                          // string
		hex.EncodeToString(d.TransactionID), // []byte
		strings.Join(opts, ""),              // []*DHCPv6Option
	})
}

func (d DHCPv6) NetcapTimestamp() string {
	return d.Timestamp
}

func (d DHCPv6Option) ToString() string {
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

func (a DHCPv6) JSON() (string, error) {
	return jsonMarshaler.MarshalToString(&a)
}

var dhcp6Metric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_DHCPv6.String()),
		Help: Type_NC_DHCPv6.String() + " audit records",
	},
	fieldsDHCPv6[1:],
)

func init() {
	prometheus.MustRegister(dhcp6Metric)
}

func (a DHCPv6) Inc() {
	dhcp6Metric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}
