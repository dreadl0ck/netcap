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

var fieldsDiameter = []string{
	"Timestamp",
	"Version",       // uint32
	"Flags",         // uint32
	"MessageLen",    // uint32
	"CommandCode",   // uint32
	"ApplicationID", // uint32
	"HopByHopID",    // uint32
	"EndToEndID",    // uint32
	"AVPs",          // []*AVP
	"SrcIP",
	"DstIP",
	"SrcPort",
	"DstPort",
}

func (a Diameter) CSVHeader() []string {
	return filter(fieldsDiameter)
}

func (a Diameter) CSVRecord() []string {
	// prevent accessing nil pointer
	if a.Context == nil {
		a.Context = &PacketContext{}
	}
	var avps []string
	for _, a := range a.AVPs {
		avps = append(avps, a.String())
	}
	return filter([]string{
		formatTimestamp(a.Timestamp),
		formatUint32(a.Version), //       uint32
		formatUint32(a.Flags), //         uint32
		formatUint32(a.MessageLen), //    uint32
		formatUint32(a.CommandCode), //   uint32
		formatUint32(a.ApplicationID), // uint32
		formatUint32(a.HopByHopID), //    uint32
		formatUint32(a.EndToEndID), //    uint32
		join(avps...), //     []*AVP
		a.Context.SrcIP,
		a.Context.DstIP,
		a.Context.SrcPort,
		a.Context.DstPort,
	})
}

func (a Diameter) Time() string {
	return a.Timestamp
}

func (a Diameter) JSON() (string, error) {
	return jsonMarshaler.MarshalToString(&a)
}

var diameterMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_Diameter.String()),
		Help: Type_NC_Diameter.String() + " audit records",
	},
	fieldsDiameter[1:],
)

func init() {
	prometheus.MustRegister(arpMetric)
}

func (a Diameter) Inc() {
	diameterMetric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

func (a *Diameter) SetPacketContext(ctx *PacketContext) {
	a.Context = ctx
}

func (a Diameter) Src() string {
	if a.Context != nil {
		return a.Context.SrcIP
	}
	return ""
}

func (a Diameter) Dst() string {
	if a.Context != nil {
		return a.Context.DstIP
	}
	return ""
}
