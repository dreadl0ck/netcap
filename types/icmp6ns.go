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
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

var fieldsICMPv6NeighborSolicitation = []string{
	"Timestamp",
	"TargetAddress", // string
	"Options",       // []*ICMPv6Option
}

func (i ICMPv6NeighborSolicitation) CSVHeader() []string {
	return filter(fieldsICMPv6NeighborSolicitation)
}

func (i ICMPv6NeighborSolicitation) CSVRecord() []string {
	var opts []string
	for _, o := range i.Options {
		opts = append(opts, o.ToString())
	}
	return filter([]string{
		formatTimestamp(i.Timestamp),
		i.TargetAddress,
		strings.Join(opts, ""),
	})
}

func (i ICMPv6NeighborSolicitation) NetcapTimestamp() string {
	return i.Timestamp
}

func (a ICMPv6NeighborSolicitation) JSON() (string, error) {
	return jsonMarshaler.MarshalToString(&a)
}

var icmp6nsMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_ICMPv6NeighborSolicitation.String()),
		Help: Type_NC_ICMPv6NeighborSolicitation.String() + " audit records",
	},
	fieldsICMPv6NeighborSolicitation[1:],
)

func init() {
	prometheus.MustRegister(icmp6nsMetric)
}

func (a ICMPv6NeighborSolicitation) Inc() {
	icmp6nsMetric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}
