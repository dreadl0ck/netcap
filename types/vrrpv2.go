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

var fieldsVRRPv2 = []string{
	"Timestamp",
	"Version",      // int32
	"Type",         // int32
	"VirtualRtrID", // int32
	"Priority",     // int32
	"CountIPAddr",  // int32
	"AuthType",     // int32
	"AdverInt",     // int32
	"Checksum",     // int32
	"IPAdresses",   // []string
}

func (a VRRPv2) CSVHeader() []string {
	return filter(fieldsVRRPv2)
}

func (a VRRPv2) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(a.Timestamp),
		formatInt32(a.Version),      // int32
		formatInt32(a.Type),         // int32
		formatInt32(a.VirtualRtrID), // int32
		formatInt32(a.Priority),     // int32
		formatInt32(a.CountIPAddr),  // int32
		formatInt32(a.AuthType),     // int32
		formatInt32(a.AdverInt),     // int32
		formatInt32(a.Checksum),     // int32
		join(a.IPAddress...),        // []string
	})
}

func (a VRRPv2) NetcapTimestamp() string {
	return a.Timestamp
}

func (a VRRPv2) JSON() (string, error) {
	return jsonMarshaler.MarshalToString(&a)
}

var vrrp2Metric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_VRRPv2.String()),
		Help: Type_NC_VRRPv2.String() + " audit records",
	},
	fieldsVRRPv2[1:],
)

func init() {
	prometheus.MustRegister(vrrp2Metric)
}

func (a VRRPv2) Inc() {
	vrrp2Metric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}
