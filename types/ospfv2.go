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
	"github.com/dreadl0ck/netcap/encoder"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	fieldPacketLength   = "PacketLength"
	fieldRouterID       = "RouterID"
	fieldAreaID         = "AreaID"
	fieldAuType         = "AuType"
	fieldAuthentication = "Authentication"
	fieldLSAs           = "LSAs"
	fieldLSU            = "LSU"
	fieldLSR            = "LSR"
	fieldDbDesc         = "DbDesc"
	fieldHelloV2        = "HelloV2"
)

var fieldsOSPFv2 = []string{
	fieldTimestamp,
	fieldVersion,        // int32
	fieldType,           // int32
	fieldPacketLength,   // int32
	fieldRouterID,       // uint32
	fieldAreaID,         // uint32
	fieldChecksum,       // int32
	fieldAuType,         // int32
	fieldAuthentication, // int64
	fieldLSAs,           // []*LSAheader
	fieldLSU,            // *LSUpdate
	fieldLSR,            // []*LSReq
	fieldDbDesc,         // *DbDescPkg
	fieldHelloV2,        // *HelloPkgV2
	fieldSrcIP,
	fieldDstIP,
}

// CSVHeader returns the CSV header for the audit record.
func (a *OSPFv2) CSVHeader() []string {
	return filter(fieldsOSPFv2)
}

// CSVRecord returns the CSV record for the audit record.
func (a *OSPFv2) CSVRecord() []string {
	var (
		lsas   []string
		lsreqs []string
	)
	for _, l := range a.LSAs {
		lsas = append(lsas, toString(l))
	}
	for _, l := range a.LSR {
		lsreqs = append(lsreqs, toString(l))
	}

	return filter([]string{
		formatTimestamp(a.Timestamp),
		formatInt32(a.Version),        // int32
		formatInt32(a.Type),           // int32
		formatInt32(a.PacketLength),   // int32
		formatUint32(a.RouterID),      // uint32
		formatUint32(a.AreaID),        // uint32
		formatInt32(a.Checksum),       // int32
		formatInt32(a.AuType),         // int32
		formatInt64(a.Authentication), // int64
		join(lsas...),                 // []*LSAheader
		toString(a.LSU),               // *LSUpdate
		join(lsreqs...),               // []*LSReq
		toString(a.DbDesc),            // *DbDescPkg
		toString(a.HelloV2),           // *HelloPkgV2
		a.SrcIP,
		a.DstIP,
	})
}

// Time returns the timestamp associated with the audit record.
func (a *OSPFv2) Time() int64 {
	return a.Timestamp
}

func (l LSReq) toString() string {
	var b strings.Builder

	b.WriteString(StructureBegin)
	b.WriteString(formatInt32(l.LSType)) // int32
	b.WriteString(FieldSeparator)
	b.WriteString(formatUint32(l.LSID)) // uint32
	b.WriteString(FieldSeparator)
	b.WriteString(formatUint32(l.AdvRouter)) // uint32
	b.WriteString(StructureEnd)

	return b.String()
}

func (r *RouterLSAV2) toString() string {
	var routers []string
	for _, e := range r.Routers {
		routers = append(routers, toString(e))
	}

	var b strings.Builder

	b.WriteString(StructureBegin)
	b.WriteString(formatInt32(r.Flags)) // int32
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(r.Links)) // int32
	b.WriteString(FieldSeparator)
	b.WriteString(join(routers...)) // []*RouterV2
	b.WriteString(StructureEnd)

	return b.String()
}

func (r *ASExternalLSAV2) toString() string {
	var b strings.Builder

	b.WriteString(StructureBegin)
	b.WriteString(formatUint32(r.NetworkMask)) // uint32
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(r.ExternalBit)) // int32
	b.WriteString(FieldSeparator)
	b.WriteString(formatUint32(r.Metric)) // uint32
	b.WriteString(FieldSeparator)
	b.WriteString(formatUint32(r.ForwardingAddress)) // uint32
	b.WriteString(FieldSeparator)
	b.WriteString(formatUint32(r.ExternalRouteTag)) // uint32
	b.WriteString(StructureEnd)

	return b.String()
}

func (r *RouterLSA) toString() string {
	var routers []string
	for _, e := range r.Routers {
		routers = append(routers, toString(e))
	}

	var b strings.Builder

	b.WriteString(StructureBegin)
	b.WriteString(formatInt32(r.Flags)) //  int32
	b.WriteString(FieldSeparator)
	b.WriteString(formatUint32(r.Options)) //  uint32
	b.WriteString(FieldSeparator)
	b.WriteString(join(routers...)) //  []*Router
	b.WriteString(StructureEnd)

	return b.String()
}

func (r *NetworkLSA) toString() string {
	var b strings.Builder

	b.WriteString(StructureBegin)
	b.WriteString(formatUint32(r.Options)) //    uint32
	b.WriteString(FieldSeparator)
	b.WriteString(joinUints(r.AttachedRouter)) // []uint32
	b.WriteString(StructureEnd)

	return b.String()
}

func (r *InterAreaPrefixLSA) toString() string {
	var b strings.Builder

	b.WriteString(StructureBegin)
	b.WriteString(formatUint32(r.Metric)) // uint32
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(r.PrefixLength)) // int32
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(r.PrefixOptions)) // int32
	b.WriteString(FieldSeparator)
	b.WriteString(hex.EncodeToString(r.AddressPrefix)) // []byte
	b.WriteString(StructureEnd)

	return b.String()
}

func (r *InterAreaRouterLSA) toString() string {
	var b strings.Builder

	b.WriteString(StructureBegin)
	b.WriteString(formatUint32(r.Options)) // uint32
	b.WriteString(FieldSeparator)
	b.WriteString(formatUint32(r.Metric)) // uint32
	b.WriteString(FieldSeparator)
	b.WriteString(formatUint32(r.DestinationRouterID)) // uint32
	b.WriteString(StructureEnd)

	return b.String()
}

func (r *ASExternalLSA) toString() string {
	var b strings.Builder

	b.WriteString(StructureBegin)
	b.WriteString(formatInt32(r.Flags)) // int32
	b.WriteString(FieldSeparator)
	b.WriteString(formatUint32(r.Metric)) // uint32
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(r.PrefixLength)) // int32
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(r.PrefixOptions)) // int32
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(r.RefLSType)) // int32
	b.WriteString(FieldSeparator)
	b.WriteString(hex.EncodeToString(r.AddressPrefix)) // []byte
	b.WriteString(FieldSeparator)
	b.WriteString(hex.EncodeToString(r.ForwardingAddress)) // []byte
	b.WriteString(FieldSeparator)
	b.WriteString(formatUint32(r.ExternalRouteTag)) // uint32
	b.WriteString(FieldSeparator)
	b.WriteString(formatUint32(r.RefLinkStateID)) // uint32
	b.WriteString(StructureEnd)

	return b.String()
}

func (r *LinkLSA) toString() string {
	var prefixes []string
	for _, p := range r.Prefixes {
		prefixes = append(prefixes, toString(p))
	}

	var b strings.Builder

	b.WriteString(StructureBegin)
	b.WriteString(formatInt32(r.RtrPriority)) // int32
	b.WriteString(FieldSeparator)
	b.WriteString(formatUint32(r.Options)) // uint32
	b.WriteString(FieldSeparator)
	b.WriteString(hex.EncodeToString(r.LinkLocalAddress)) // []byte
	b.WriteString(FieldSeparator)
	b.WriteString(formatUint32(r.NumOfPrefixes)) // uint32
	b.WriteString(FieldSeparator)
	b.WriteString(join(prefixes...)) // []*LSAPrefix
	b.WriteString(StructureEnd)

	return b.String()
}

func (r *IntraAreaPrefixLSA) toString() string {
	var prefixes []string
	for _, p := range r.Prefixes {
		prefixes = append(prefixes, toString(p))
	}

	var b strings.Builder

	b.WriteString(StructureBegin)
	b.WriteString(formatInt32(r.NumOfPrefixes)) // int32
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(r.RefLSType)) // int32
	b.WriteString(FieldSeparator)
	b.WriteString(formatUint32(r.RefLinkStateID)) // uint32
	b.WriteString(FieldSeparator)
	b.WriteString(formatUint32(r.RefAdvRouter)) // uint32
	b.WriteString(FieldSeparator)
	b.WriteString(join(prefixes...)) // []*LSAPrefix
	b.WriteString(StructureEnd)

	return b.String()
}

func (r *Router) toString() string {
	var b strings.Builder

	b.WriteString(StructureBegin)

	b.WriteString(formatInt32(r.Type)) // int32
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(r.Metric)) // int32
	b.WriteString(FieldSeparator)
	b.WriteString(formatUint32(r.InterfaceID)) // uint32
	b.WriteString(FieldSeparator)
	b.WriteString(formatUint32(r.NeighborInterfaceID)) // uint32
	b.WriteString(FieldSeparator)
	b.WriteString(formatUint32(r.NeighborRouterID)) // uint32

	b.WriteString(StructureEnd)

	return b.String()
}

func (r *RouterV2) toString() string {
	var b strings.Builder

	b.WriteString(StructureBegin)
	b.WriteString(formatInt32(r.Type)) // int32
	b.WriteString(FieldSeparator)
	b.WriteString(formatUint32(r.LinkID)) // uint32
	b.WriteString(FieldSeparator)
	b.WriteString(formatUint32(r.LinkData)) // uint32
	b.WriteString(FieldSeparator)
	b.WriteString(formatUint32(r.Metric)) // uint32
	b.WriteString(StructureEnd)

	return b.String()
}

func (l *LSA) toString() string {
	var b strings.Builder

	b.WriteString(StructureBegin)

	b.WriteString(toString(l.Header)) // *LSAheader
	b.WriteString(FieldSeparator)
	b.WriteString(toString(l.RLSAV2)) // *RouterLSAV2
	b.WriteString(FieldSeparator)
	b.WriteString(toString(l.ASELSAV2)) // *ASExternalLSAV2
	b.WriteString(FieldSeparator)
	b.WriteString(toString(l.RLSA)) // *RouterLSA
	b.WriteString(FieldSeparator)
	b.WriteString(toString(l.NLSA)) // *NetworkLSA
	b.WriteString(FieldSeparator)
	b.WriteString(toString(l.InterAPrefixLSA)) // *InterAreaPrefixLSA
	b.WriteString(FieldSeparator)
	b.WriteString(toString(l.IARouterLSA)) // *InterAreaRouterLSA
	b.WriteString(FieldSeparator)
	b.WriteString(toString(l.ASELSA)) // *ASExternalLSA
	b.WriteString(FieldSeparator)
	b.WriteString(toString(l.LLSA)) // *LinkLSA
	b.WriteString(FieldSeparator)
	b.WriteString(toString(l.IntraAPrefixLSA)) // *IntraAreaPrefixLSA

	b.WriteString(StructureEnd)

	return b.String()
}

func (l LSUpdate) toString() string {
	var lsas []string
	for _, lsa := range l.LSAs {
		lsas = append(lsas, toString(lsa))
	}

	var b strings.Builder

	b.WriteString(StructureBegin)
	b.WriteString(formatUint32(l.NumOfLSAs)) // uint32
	b.WriteString(FieldSeparator)
	b.WriteString(join(lsas...)) // []*LSA
	b.WriteString(StructureEnd)

	return b.String()
}

func (l DbDescPkg) toString() string {
	var headers []string
	for _, lsa := range l.LSAinfo {
		headers = append(headers, toString(lsa))
	}

	var b strings.Builder

	b.WriteString(StructureBegin)
	b.WriteString(formatUint32(l.Options)) // uint32
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(l.InterfaceMTU)) // int32
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(l.Flags)) // int32
	b.WriteString(FieldSeparator)
	b.WriteString(formatUint32(l.DDSeqNumber)) // uint32
	b.WriteString(FieldSeparator)
	b.WriteString(join(headers...)) // []*LSAheader
	b.WriteString(StructureEnd)

	return b.String()
}

func (l HelloPkgV2) toString() string {
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
	b.WriteString(joinUints(l.NeighborID)) //  []uint32
	b.WriteString(FieldSeparator)
	b.WriteString(formatUint32(l.NetworkMask)) // uint32
	b.WriteString(StructureEnd)

	return b.String()
}

func (l LSAPrefix) toString() string {
	var b strings.Builder

	b.WriteString(StructureBegin)
	b.WriteString(formatInt32(l.PrefixLength)) // int32
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(l.PrefixOptions)) // int32
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(l.Metric)) // int32
	b.WriteString(FieldSeparator)
	b.WriteString(hex.EncodeToString(l.AddressPrefix)) // []byte
	b.WriteString(StructureEnd)

	return b.String()
}

func (l LSAheader) toString() string {
	var b strings.Builder

	b.WriteString(StructureBegin)
	b.WriteString(formatInt32(l.LSAge)) // int32
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(l.LSType)) // int32
	b.WriteString(FieldSeparator)
	b.WriteString(formatUint32(l.LinkStateID)) // uint32
	b.WriteString(FieldSeparator)
	b.WriteString(formatUint32(l.AdvRouter)) // uint32
	b.WriteString(FieldSeparator)
	b.WriteString(formatUint32(l.LSSeqNumber)) // uint32
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(l.LSChecksum)) // int32
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(l.Length)) // int32
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(l.LSOptions)) // int32
	b.WriteString(StructureEnd)

	return b.String()
}

var ospf2Metric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_OSPFv2.String()),
		Help: Type_NC_OSPFv2.String() + " audit records",
	},
	fieldsOSPFv2[1:],
)

// Inc increments the metrics for the audit record.
func (a *OSPFv2) Inc() {
	ospf2Metric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

// JSON returns the JSON representation of the audit record.
func (a *OSPFv2) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	a.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(a)
}

// SetPacketContext sets the associated packet context for the audit record.
func (a *OSPFv2) SetPacketContext(ctx *PacketContext) {
	a.SrcIP = ctx.SrcIP
	a.DstIP = ctx.DstIP
}

// Src returns the source address of the audit record.
func (a *OSPFv2) Src() string {
	return a.SrcIP
}

// Dst returns the destination address of the audit record.
func (a *OSPFv2) Dst() string {
	return a.DstIP
}

var ospf2Encoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (a *OSPFv2) Encode() []string {
	var (
		lsas   []string
		lsreqs []string
	)
	for _, l := range a.LSAs {
		lsas = append(lsas, toString(l))
	}
	for _, l := range a.LSR {
		lsreqs = append(lsreqs, toString(l))
	}

	return filter([]string{
		ospf2Encoder.Int64(fieldTimestamp, a.Timestamp),        // int64
		ospf2Encoder.Int32(fieldVersion, a.Version),            // int32
		ospf2Encoder.Int32(fieldType, a.Type),                  // int32
		ospf2Encoder.Int32(fieldPacketLength, a.PacketLength),  // int32
		ospf2Encoder.Uint32(fieldRouterID, a.RouterID),         // uint32
		ospf2Encoder.Uint32(fieldAreaID, a.AreaID),             // uint32
		ospf2Encoder.Int32(fieldChecksum, a.Checksum),          // int32
		ospf2Encoder.Int32(fieldAuType, a.AuType),              // int32
		formatInt64(a.Authentication),                          // int64
		ospf2Encoder.String(fieldLSAs, join(lsas...)),          // []*LSAheader
		ospf2Encoder.String(fieldLSU, toString(a.LSU)),         // *LSUpdate
		ospf2Encoder.String(fieldLSR, join(lsreqs...)),         // []*LSReq
		ospf2Encoder.String(fieldDbDesc, toString(a.DbDesc)),   // *DbDescPkg
		ospf2Encoder.String(fieldHelloV2, toString(a.HelloV2)), // *HelloPkgV2
		ospf2Encoder.String(fieldSrcIP, a.SrcIP),
		ospf2Encoder.String(fieldDstIP, a.DstIP),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (a *OSPFv2) Analyze() {}

// NetcapType returns the type of the current audit record
func (n *OSPFv2) NetcapType() Type {
	return Type_NC_OSPFv2
}
