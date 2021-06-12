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
	"github.com/dreadl0ck/netcap/encoder"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	fieldInstance = "Instance"
	fieldHello    = "Hello"
)

var fieldsOSPFv3 = []string{
	fieldTimestamp,
	fieldVersion,      // int32
	fieldType,         // int32
	fieldPacketLength, // int32
	fieldRouterID,     // uint32
	fieldAreaID,       // uint32
	fieldChecksum,     // int32
	fieldInstance,     // int32
	fieldReserved,     // int32
	fieldHello,        // *HelloPkg
	fieldDbDesc,       // *DbDescPkg
	fieldLSR,          // []*LSReq
	fieldLSU,          // *LSUpdate
	fieldLSAs,         // []*LSAheader
	fieldSrcIP,
	fieldDstIP,
}

// CSVHeader returns the CSV header for the audit record.
func (a *OSPFv3) CSVHeader() []string {
	return filter(fieldsOSPFv3)
}

// CSVRecord returns the CSV record for the audit record.
func (a *OSPFv3) CSVRecord() []string {
	var (
		lsas   []string
		lsreqs []string
	)
	for _, l := range a.LSAs {
		lsas = append(lsas, l.toString())
	}
	for _, l := range a.LSR {
		lsreqs = append(lsreqs, l.toString())
	}

	return filter([]string{
		formatTimestamp(a.Timestamp),
		formatInt32(a.Version),      // int32
		formatInt32(a.Type),         // int32
		formatInt32(a.PacketLength), // int32
		formatUint32(a.RouterID),    // uint32
		formatUint32(a.AreaID),      // uint32
		formatInt32(a.Checksum),     // int32
		formatInt32(a.Instance),     // int32
		formatInt32(a.Reserved),     // int32
		toString(a.Hello),           // *HelloPkg
		toString(a.DbDesc),          // *DbDescPkg
		join(lsreqs...),             // []*LSReq
		toString(a.LSU),             // *LSUpdate
		join(lsas...),               // []*LSAheader
		a.SrcIP,
		a.DstIP,
	})
}

// Time returns the timestamp associated with the audit record.
func (a *OSPFv3) Time() int64 {
	return a.Timestamp
}

func (l HelloPkg) toString() string {
	var b strings.Builder

	b.WriteString(StructureBegin)
	b.WriteString(formatUint32(l.InterfaceID)) // uint32
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(l.RtrPriority)) // int32
	b.WriteString(FieldSeparator)
	b.WriteString(formatUint32(l.Options)) // uint32
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(l.HelloInterval)) // int32
	b.WriteString(FieldSeparator)
	b.WriteString(formatUint32(l.RouterDeadInterval)) // uint32
	b.WriteString(FieldSeparator)
	b.WriteString(formatUint32(l.DesignatedRouterID)) // uint32
	b.WriteString(FieldSeparator)
	b.WriteString(formatUint32(l.BackupDesignatedRouterID)) // uint32
	b.WriteString(FieldSeparator)
	b.WriteString(joinUints(l.NeighborID)) // []uint32
	b.WriteString(StructureEnd)

	return b.String()
}

var ospf3Metric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_OSPFv3.String()),
		Help: Type_NC_OSPFv3.String() + " audit records",
	},
	fieldsOSPFv3[1:],
)

// Inc increments the metrics for the audit record.
func (a *OSPFv3) Inc() {
	ospf3Metric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

// JSON returns the JSON representation of the audit record.
func (a *OSPFv3) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	a.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(a)
}

// SetPacketContext sets the associated packet context for the audit record.
func (a *OSPFv3) SetPacketContext(ctx *PacketContext) {
	a.SrcIP = ctx.SrcIP
	a.DstIP = ctx.DstIP
}

// Src returns the source address of the audit record.
func (a *OSPFv3) Src() string {
	return a.SrcIP
}

// Dst returns the destination address of the audit record.
func (a *OSPFv3) Dst() string {
	return a.DstIP
}

var ospf3Encoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (a *OSPFv3) Encode() []string {

	var (
		lsas   []string
		lsreqs []string
	)
	for _, l := range a.LSAs {
		lsas = append(lsas, l.toString())
	}
	for _, l := range a.LSR {
		lsreqs = append(lsreqs, l.toString())
	}

	return filter([]string{
		ospf3Encoder.Int64(fieldTimestamp, a.Timestamp),
		ospf3Encoder.Int32(fieldVersion, a.Version),           // int32
		ospf3Encoder.Int32(fieldType, a.Type),                 // int32
		ospf3Encoder.Int32(fieldPacketLength, a.PacketLength), // int32
		ospf3Encoder.Uint32(fieldRouterID, a.RouterID),        // uint32
		ospf3Encoder.Uint32(fieldAreaID, a.AreaID),            // uint32
		ospf3Encoder.Int32(fieldChecksum, a.Checksum),         // int32
		ospf3Encoder.Int32(fieldInstance, a.Instance),         // int32
		ospf3Encoder.Int32(fieldReserved, a.Reserved),         // int32
		ospf3Encoder.String(fieldHello, toString(a.Hello)),    // *HelloPkg
		ospf3Encoder.String(fieldDbDesc, toString(a.DbDesc)),  // *DbDescPkg
		ospf3Encoder.String(fieldLSR, join(lsreqs...)),        // []*LSReq
		ospf3Encoder.String(fieldLSU, toString(a.LSU)),        // *LSUpdate
		ospf3Encoder.String(fieldLSAs, join(lsas...)),         // []*LSAheader
		ospf2Encoder.String(fieldSrcIP, a.SrcIP),
		ospf2Encoder.String(fieldDstIP, a.DstIP),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (a *OSPFv3) Analyze() {}

// NetcapType returns the type of the current audit record
func (a *OSPFv3) NetcapType() Type {
	return Type_NC_OSPFv3
}
