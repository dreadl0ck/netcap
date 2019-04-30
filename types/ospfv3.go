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

import "strings"

func (a OSPFv3) CSVHeader() []string {
	return filter([]string{
		"Timestamp",
		"Version",      // int32
		"Type",         // int32
		"PacketLength", // int32
		"RouterID",     // uint32
		"AreaID",       // uint32
		"Checksum",     // int32
		"Instance",     // int32
		"Reserved",     // int32
		"Hello",        // *HelloPkg
		"DbDesc",       // *DbDescPkg
		"LSR",          // []*LSReq
		"LSU",          // *LSUpdate
		"LSAs",         // []*LSAheader
	})
}

func (a OSPFv3) CSVRecord() []string {
	var (
		lsas   []string
		lsreqs []string
	)
	for _, l := range a.LSAs {
		lsas = append(lsas, l.ToString())
	}
	for _, l := range a.LSR {
		lsreqs = append(lsreqs, l.ToString())
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
	})
}

func (a OSPFv3) NetcapTimestamp() string {
	return a.Timestamp
}

func (l HelloPkg) ToString() string {

	var b strings.Builder

	b.WriteString(Begin)
	b.WriteString(formatUint32(l.InterfaceID)) // uint32
	b.WriteString(Separator)
	b.WriteString(formatInt32(l.RtrPriority)) // int32
	b.WriteString(Separator)
	b.WriteString(formatUint32(l.Options)) // uint32
	b.WriteString(Separator)
	b.WriteString(formatInt32(l.HelloInterval)) // int32
	b.WriteString(Separator)
	b.WriteString(formatUint32(l.RouterDeadInterval)) // uint32
	b.WriteString(Separator)
	b.WriteString(formatUint32(l.DesignatedRouterID)) // uint32
	b.WriteString(Separator)
	b.WriteString(formatUint32(l.BackupDesignatedRouterID)) // uint32
	b.WriteString(Separator)
	b.WriteString(joinUints(l.NeighborID)) // []uint32
	b.WriteString(End)

	return b.String()
}

func (u HelloPkg) JSON() (string, error) {
	return jsonMarshaler.MarshalToString(&u)
}
