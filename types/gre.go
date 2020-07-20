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
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

var fieldsGRE = []string{
	"Timestamp",
	"ChecksumPresent",   // bool
	"RoutingPresent",    // bool
	"KeyPresent",        // bool
	"SeqPresent",        // bool
	"StrictSourceRoute", // bool
	"AckPresent",        // bool
	"RecursionControl",  // int32
	"Flags",             // int32
	"Version",           // int32
	"Protocol",          // int32
	"Checksum",          // int32
	"Offset",            // int32
	"Key",               // uint32
	"Seq",               // uint32
	"Ack",               // uint32
	"Routing",           // *GRERouting
	"SrcIP",
	"DstIP",
	"SrcPort",
	"DstPort",
}

func (a *GRE) CSVHeader() []string {
	return filter(fieldsGRE)
}

func (a *GRE) CSVRecord() []string {
	// prevent accessing nil pointer
	if a.Context == nil {
		a.Context = &PacketContext{}
	}
	return filter([]string{
		formatTimestamp(a.Timestamp),
		strconv.FormatBool(a.ChecksumPresent),   // bool
		strconv.FormatBool(a.RoutingPresent),    // bool
		strconv.FormatBool(a.KeyPresent),        // bool
		strconv.FormatBool(a.SeqPresent),        // bool
		strconv.FormatBool(a.StrictSourceRoute), // bool
		strconv.FormatBool(a.AckPresent),        // bool
		formatInt32(a.RecursionControl),         // int32
		formatInt32(a.Flags),                    // int32
		formatInt32(a.Version),                  // int32
		formatInt32(a.Protocol),                 // int32
		formatInt32(a.Checksum),                 // int32
		formatInt32(a.Offset),                   // int32
		formatUint32(a.Key),                     // uint32
		formatUint32(a.Seq),                     // uint32
		formatUint32(a.Ack),                     // uint32
		a.Routing.GetString(),                   // *GRERouting
		a.Context.SrcIP,
		a.Context.DstIP,
		a.Context.SrcPort,
		a.Context.DstPort,
	})
}

func (a *GRE) Time() string {
	return a.Timestamp
}

func (r *GRERouting) GetString() string {

	if r == nil {
		return ""
	}

	var b strings.Builder

	b.WriteString(Begin)
	b.WriteString(formatInt32(r.AddressFamily))
	b.WriteString(Separator)
	b.WriteString(formatInt32(r.SREOffset))
	b.WriteString(Separator)
	b.WriteString(formatInt32(r.SRELength))
	b.WriteString(Separator)
	b.WriteString(hex.EncodeToString(r.RoutingInformation))
	b.WriteString(Separator)
	b.WriteString(r.Next.GetString())
	b.WriteString(End)

	return b.String()
}

func (a *GRE) JSON() (string, error) {
	return jsonMarshaler.MarshalToString(a)
}

var greMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_GRE.String()),
		Help: Type_NC_GRE.String() + " audit records",
	},
	fieldsGRE[1:],
)

func init() {
	prometheus.MustRegister(greMetric)
}

func (a *GRE) Inc() {
	greMetric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

func (a *GRE) SetPacketContext(ctx *PacketContext) {
	a.Context = ctx
}

func (a *GRE) Src() string {
	if a.Context != nil {
		return a.Context.SrcIP
	}
	return ""
}

func (a *GRE) Dst() string {
	if a.Context != nil {
		return a.Context.DstIP
	}
	return ""
}
