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

var fieldsCiscoDiscovery = []string{
	"Timestamp",
	"Version",  // int32
	"TTL",      // int32
	"Checksum", // int32
	"Values",   // []*CiscoDiscoveryValue
}

func (a CiscoDiscovery) CSVHeader() []string {
	return filter(fieldsCiscoDiscovery)
}

func (a CiscoDiscovery) CSVRecord() []string {
	var vals []string
	for _, v := range a.Values {
		vals = append(vals, v.ToString())
	}
	return filter([]string{
		formatTimestamp(a.Timestamp),
		formatInt32(a.Version),  // int32
		formatInt32(a.TTL),      // int32
		formatInt32(a.Checksum), // int32
		join(vals...),           // []*CiscoDiscoveryValue
	})
}

func (a CiscoDiscovery) Time() string {
	return a.Timestamp
}

func (v CiscoDiscoveryValue) ToString() string {

	var b strings.Builder
	b.WriteString(Begin)
	b.WriteString(formatInt32(v.Type))
	b.WriteString(Separator)
	b.WriteString(formatInt32(v.Length))
	b.WriteString(Separator)
	b.WriteString(hex.EncodeToString(v.Value))
	b.WriteString(End)
	return b.String()
}

func (a CiscoDiscovery) JSON() (string, error) {
	return jsonMarshaler.MarshalToString(&a)
}

var ciscoDiscoveryMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_CiscoDiscovery.String()),
		Help: Type_NC_CiscoDiscovery.String() + " audit records",
	},
	fieldsCiscoDiscovery[1:],
)

func init() {
	prometheus.MustRegister(ciscoDiscoveryMetric)
}

func (a CiscoDiscovery) Inc() {
	ciscoDiscoveryMetric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

func (a *CiscoDiscovery) SetPacketContext(ctx *PacketContext) {}

// TODO
func (a CiscoDiscovery) Src() string {
	return ""
}

func (a CiscoDiscovery) Dst() string {
	return ""
}
