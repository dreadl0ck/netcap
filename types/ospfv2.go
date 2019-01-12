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
)

func (a OSPFv2) CSVHeader() []string {
	return filter([]string{
		"Timestamp",
		"Version",        // int32
		"Type",           // int32
		"PacketLength",   // int32
		"RouterID",       // uint32
		"AreaID",         // uint32
		"Checksum",       // int32
		"AuType",         // int32
		"Authentication", // int64
		"LSAs",           // []*LSAheader
		"LSU",            // *LSUpdate
		"LSR",            // []*LSReq
		"DbDesc",         // *DbDescPkg
		"HelloV2",        // *HelloPkgV2
	})
}

func (a OSPFv2) CSVRecord() []string {
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
	})
}

func (a OSPFv2) NetcapTimestamp() string {
	return a.Timestamp
}

func (l LSReq) ToString() string {
	var b strings.Builder

	b.WriteString(begin)
	b.WriteString(formatInt32(l.LSType)) // int32
	b.WriteString(sep)
	b.WriteString(formatUint32(l.LSID)) // uint32
	b.WriteString(sep)
	b.WriteString(formatUint32(l.AdvRouter)) // uint32
	b.WriteString(end)

	return b.String()
}

func (r RouterLSAV2) ToString() string {

	var routers []string
	for _, e := range r.Routers {
		routers = append(routers, toString(e))
	}

	var b strings.Builder

	b.WriteString(begin)
	b.WriteString(formatInt32(r.Flags)) // int32
	b.WriteString(sep)
	b.WriteString(formatInt32(r.Links)) // int32
	b.WriteString(sep)
	b.WriteString(join(routers...)) // []*RouterV2
	b.WriteString(end)

	return b.String()
}

func (r ASExternalLSAV2) ToString() string {
	var b strings.Builder

	b.WriteString(begin)
	b.WriteString(formatUint32(r.NetworkMask)) // uint32
	b.WriteString(sep)
	b.WriteString(formatInt32(r.ExternalBit)) // int32
	b.WriteString(sep)
	b.WriteString(formatUint32(r.Metric)) // uint32
	b.WriteString(sep)
	b.WriteString(formatUint32(r.ForwardingAddress)) // uint32
	b.WriteString(sep)
	b.WriteString(formatUint32(r.ExternalRouteTag)) // uint32
	b.WriteString(end)

	return b.String()
}

func (r RouterLSA) ToString() string {

	var routers []string
	for _, e := range r.Routers {
		routers = append(routers, toString(e))
	}

	var b strings.Builder

	b.WriteString(begin)
	b.WriteString(formatInt32(r.Flags)) //  int32
	b.WriteString(sep)
	b.WriteString(formatUint32(r.Options)) //  uint32
	b.WriteString(sep)
	b.WriteString(join(routers...)) //  []*Router
	b.WriteString(end)

	return b.String()
}

func (r NetworkLSA) ToString() string {
	var b strings.Builder

	b.WriteString(begin)
	b.WriteString(formatUint32(r.Options)) //    uint32
	b.WriteString(sep)
	b.WriteString(joinUints(r.AttachedRouter)) // []uint32
	b.WriteString(end)

	return b.String()
}

func (r InterAreaPrefixLSA) ToString() string {
	var b strings.Builder

	b.WriteString(begin)
	b.WriteString(formatUint32(r.Metric)) // uint32
	b.WriteString(sep)
	b.WriteString(formatInt32(r.PrefixLength)) // int32
	b.WriteString(sep)
	b.WriteString(formatInt32(r.PrefixOptions)) // int32
	b.WriteString(sep)
	b.WriteString(hex.EncodeToString(r.AddressPrefix)) // []byte
	b.WriteString(end)

	return b.String()
}

func (r InterAreaRouterLSA) ToString() string {
	var b strings.Builder

	b.WriteString(begin)
	b.WriteString(formatUint32(r.Options)) // uint32
	b.WriteString(sep)
	b.WriteString(formatUint32(r.Metric)) // uint32
	b.WriteString(sep)
	b.WriteString(formatUint32(r.DestinationRouterID)) // uint32
	b.WriteString(end)

	return b.String()
}

func (r ASExternalLSA) ToString() string {
	var b strings.Builder

	b.WriteString(begin)
	b.WriteString(formatInt32(r.Flags)) // int32
	b.WriteString(sep)
	b.WriteString(formatUint32(r.Metric)) // uint32
	b.WriteString(sep)
	b.WriteString(formatInt32(r.PrefixLength)) // int32
	b.WriteString(sep)
	b.WriteString(formatInt32(r.PrefixOptions)) // int32
	b.WriteString(sep)
	b.WriteString(formatInt32(r.RefLSType)) // int32
	b.WriteString(sep)
	b.WriteString(hex.EncodeToString(r.AddressPrefix)) // []byte
	b.WriteString(sep)
	b.WriteString(hex.EncodeToString(r.ForwardingAddress)) // []byte
	b.WriteString(sep)
	b.WriteString(formatUint32(r.ExternalRouteTag)) // uint32
	b.WriteString(sep)
	b.WriteString(formatUint32(r.RefLinkStateID)) // uint32
	b.WriteString(end)

	return b.String()
}

func (r LinkLSA) ToString() string {

	var prefixes []string
	for _, p := range r.Prefixes {
		prefixes = append(prefixes, toString(p))
	}

	var b strings.Builder

	b.WriteString(begin)
	b.WriteString(formatInt32(r.RtrPriority)) // int32
	b.WriteString(sep)
	b.WriteString(formatUint32(r.Options)) // uint32
	b.WriteString(sep)
	b.WriteString(hex.EncodeToString(r.LinkLocalAddress)) // []byte
	b.WriteString(sep)
	b.WriteString(formatUint32(r.NumOfPrefixes)) // uint32
	b.WriteString(sep)
	b.WriteString(join(prefixes...)) // []*LSAPrefix
	b.WriteString(end)

	return b.String()
}

func (r IntraAreaPrefixLSA) ToString() string {

	var prefixes []string
	for _, p := range r.Prefixes {
		prefixes = append(prefixes, toString(p))
	}

	var b strings.Builder

	b.WriteString(begin)
	b.WriteString(formatInt32(r.NumOfPrefixes)) // int32
	b.WriteString(sep)
	b.WriteString(formatInt32(r.RefLSType)) // int32
	b.WriteString(sep)
	b.WriteString(formatUint32(r.RefLinkStateID)) // uint32
	b.WriteString(sep)
	b.WriteString(formatUint32(r.RefAdvRouter)) // uint32
	b.WriteString(sep)
	b.WriteString(join(prefixes...)) // []*LSAPrefix
	b.WriteString(end)

	return b.String()
}

func (r Router) ToString() string {
	var b strings.Builder

	b.WriteString(begin)

	b.WriteString(formatInt32(r.Type)) // int32
	b.WriteString(sep)
	b.WriteString(formatInt32(r.Metric)) // int32
	b.WriteString(sep)
	b.WriteString(formatUint32(r.InterfaceID)) // uint32
	b.WriteString(sep)
	b.WriteString(formatUint32(r.NeighborInterfaceID)) // uint32
	b.WriteString(sep)
	b.WriteString(formatUint32(r.NeighborRouterID)) // uint32

	b.WriteString(end)

	return b.String()
}

func (r RouterV2) ToString() string {
	var b strings.Builder

	b.WriteString(begin)
	b.WriteString(formatInt32(r.Type)) // int32
	b.WriteString(sep)
	b.WriteString(formatUint32(r.LinkID)) // uint32
	b.WriteString(sep)
	b.WriteString(formatUint32(r.LinkData)) // uint32
	b.WriteString(sep)
	b.WriteString(formatUint32(r.Metric)) // uint32
	b.WriteString(end)

	return b.String()
}

func (l LSA) ToString() string {

	var b strings.Builder

	b.WriteString(begin)

	b.WriteString(toString(l.Header)) // *LSAheader
	b.WriteString(sep)
	b.WriteString(toString(l.RLSAV2)) // *RouterLSAV2
	b.WriteString(sep)
	b.WriteString(toString(l.ASELSAV2)) // *ASExternalLSAV2
	b.WriteString(sep)
	b.WriteString(toString(l.RLSA)) // *RouterLSA
	b.WriteString(sep)
	b.WriteString(toString(l.NLSA)) // *NetworkLSA
	b.WriteString(sep)
	b.WriteString(toString(l.InterAPrefixLSA)) // *InterAreaPrefixLSA
	b.WriteString(sep)
	b.WriteString(toString(l.IARouterLSA)) // *InterAreaRouterLSA
	b.WriteString(sep)
	b.WriteString(toString(l.ASELSA)) // *ASExternalLSA
	b.WriteString(sep)
	b.WriteString(toString(l.LLSA)) // *LinkLSA
	b.WriteString(sep)
	b.WriteString(toString(l.IntraAPrefixLSA)) // *IntraAreaPrefixLSA

	b.WriteString(end)

	return b.String()
}

func (l LSUpdate) ToString() string {

	var lsas []string
	for _, lsa := range l.LSAs {
		lsas = append(lsas, toString(lsa))
	}

	var b strings.Builder

	b.WriteString(begin)
	b.WriteString(formatUint32(l.NumOfLSAs)) // uint32
	b.WriteString(sep)
	b.WriteString(join(lsas...)) // []*LSA
	b.WriteString(end)

	return b.String()
}

func (l DbDescPkg) ToString() string {

	var headers []string
	for _, lsa := range l.LSAinfo {
		headers = append(headers, toString(lsa))
	}

	var b strings.Builder

	b.WriteString(begin)
	b.WriteString(formatUint32(l.Options)) // uint32
	b.WriteString(sep)
	b.WriteString(formatInt32(l.InterfaceMTU)) // int32
	b.WriteString(sep)
	b.WriteString(formatInt32(l.Flags)) // int32
	b.WriteString(sep)
	b.WriteString(formatUint32(l.DDSeqNumber)) // uint32
	b.WriteString(sep)
	b.WriteString(join(headers...)) // []*LSAheader
	b.WriteString(end)

	return b.String()
}

func (l HelloPkgV2) ToString() string {

	var b strings.Builder

	b.WriteString(begin)
	b.WriteString(formatUint32(l.InterfaceID)) // uint32
	b.WriteString(sep)
	b.WriteString(formatInt32(l.RtrPriority)) // int32
	b.WriteString(sep)
	b.WriteString(formatUint32(l.Options)) // uint32
	b.WriteString(sep)
	b.WriteString(formatInt32(l.HelloInterval)) // int32
	b.WriteString(sep)
	b.WriteString(formatUint32(l.RouterDeadInterval)) // uint32
	b.WriteString(sep)
	b.WriteString(formatUint32(l.DesignatedRouterID)) // uint32
	b.WriteString(sep)
	b.WriteString(formatUint32(l.BackupDesignatedRouterID)) // uint32
	b.WriteString(sep)
	b.WriteString(joinUints(l.NeighborID)) //  []uint32
	b.WriteString(sep)
	b.WriteString(formatUint32(l.NetworkMask)) // uint32
	b.WriteString(end)

	return b.String()
}

func (l LSAPrefix) ToString() string {
	var b strings.Builder

	b.WriteString(begin)
	b.WriteString(formatInt32(l.PrefixLength)) // int32
	b.WriteString(sep)
	b.WriteString(formatInt32(l.PrefixOptions)) // int32
	b.WriteString(sep)
	b.WriteString(formatInt32(l.Metric)) // int32
	b.WriteString(sep)
	b.WriteString(hex.EncodeToString(l.AddressPrefix)) // []byte
	b.WriteString(end)

	return b.String()
}

func (l LSAheader) ToString() string {

	var b strings.Builder

	b.WriteString(begin)
	b.WriteString(formatInt32(l.LSAge)) // int32
	b.WriteString(sep)
	b.WriteString(formatInt32(l.LSType)) // int32
	b.WriteString(sep)
	b.WriteString(formatUint32(l.LinkStateID)) // uint32
	b.WriteString(sep)
	b.WriteString(formatUint32(l.AdvRouter)) // uint32
	b.WriteString(sep)
	b.WriteString(formatUint32(l.LSSeqNumber)) // uint32
	b.WriteString(sep)
	b.WriteString(formatInt32(l.LSChecksum)) // int32
	b.WriteString(sep)
	b.WriteString(formatInt32(l.Length)) // int32
	b.WriteString(sep)
	b.WriteString(formatInt32(l.LSOptions)) // int32
	b.WriteString(end)

	return b.String()
}
