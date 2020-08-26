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
	"time"

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

// CSVHeader returns the CSV header for the audit record.
func (i *Geneve) CSVHeader() []string {
	return filter(fieldsGeneve)
}

// CSVRecord returns the CSV record for the audit record.
func (i *Geneve) CSVRecord() []string {
	var opts []string
	for _, o := range i.Options {
		opts = append(opts, o.toString())
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
	})
}

// Time returns the timestamp associated with the audit record.
func (i *Geneve) Time() int64 {
	return i.Timestamp
}

func (i GeneveOption) toString() string {
	var b strings.Builder
	b.WriteString(StructureBegin)
	b.WriteString(formatInt32(i.Class))
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(i.Type))
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(i.Flags))
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(i.Length))
	b.WriteString(FieldSeparator)
	b.WriteString(hex.EncodeToString(i.Data))
	b.WriteString(StructureEnd)

	return b.String()
}

// JSON returns the JSON representation of the audit record.
func (i *Geneve) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	i.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(i)
}

var geneveMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_Geneve.String()),
		Help: Type_NC_Geneve.String() + " audit records",
	},
	fieldsGeneve[1:],
)

// Inc increments the metrics for the audit record.
func (i *Geneve) Inc() {
	geneveMetric.WithLabelValues(i.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (i *Geneve) SetPacketContext(_ *PacketContext) {}

// Src returns the source address of the audit record.
func (i *Geneve) Src() string {
	return ""
}

// Dst returns the destination address of the audit record.
func (i *Geneve) Dst() string {
	return ""
}
