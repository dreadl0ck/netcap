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
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

var fieldsGeneve = []string{
	"Timestamp",
	"Version",        // int32
	"OptionsLength",  // int32
	"OAMPacket",      // bool
	"CriticalOption", // bool
	"Protocol",       // int32
	"VNI",            // uint32
	"Options",        // []*GeneveOption
	"SrcIP",
	"DstIP",
	"SrcPort",
	"DstPort",
}

func (i Geneve) CSVHeader() []string {
	return filter(fieldsGeneve)
}

func (i Geneve) CSVRecord() []string {
	var opts []string
	for _, o := range i.Options {
		opts = append(opts, o.ToString())
	}
	return filter([]string{
		formatTimestamp(i.Timestamp),
		formatInt32(i.Version),               // int32
		formatInt32(i.OptionsLength),         // int32
		strconv.FormatBool(i.OAMPacket),      // bool
		strconv.FormatBool(i.CriticalOption), // bool
		formatInt32(i.Protocol),              // int32
		formatUint32(i.VNI),                  // uint32
		strings.Join(opts, ""),               // []*GeneveOption
		i.Context.SrcIP,
		i.Context.DstIP,
		i.Context.SrcPort,
		i.Context.DstPort,
	})
}

func (i Geneve) NetcapTimestamp() string {
	return i.Timestamp
}

func (i GeneveOption) ToString() string {

	var b strings.Builder
	b.WriteString(Begin)
	b.WriteString(formatInt32(i.Class))
	b.WriteString(Separator)
	b.WriteString(formatInt32(i.Type))
	b.WriteString(Separator)
	b.WriteString(formatInt32(i.Flags))
	b.WriteString(Separator)
	b.WriteString(formatInt32(i.Length))
	b.WriteString(Separator)
	b.WriteString(hex.EncodeToString(i.Data))
	b.WriteString(End)

	return b.String()
}

func (a Geneve) JSON() (string, error) {
	return jsonMarshaler.MarshalToString(&a)
}

var geneveMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_Geneve.String()),
		Help: Type_NC_Geneve.String() + " audit records",
	},
	fieldsGeneve[1:],
)

func init() {
	prometheus.MustRegister(geneveMetric)
}

func (a Geneve) Inc() {
	geneveMetric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

func (a *Geneve) SetPacketContext(ctx *PacketContext) {
	a.Context = ctx
}
