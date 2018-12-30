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
	})
}

func (a OSPFv3) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(a.Timestamp),
		formatInt32(a.Version),      //  int32
		formatInt32(a.Type),         //  int32
		formatInt32(a.PacketLength), //  int32
		formatUint32(a.RouterID),    //  uint32
		formatUint32(a.AreaID),      //  uint32
		formatInt32(a.Checksum),     //  int32
		formatInt32(a.Instance),     // int32
		formatInt32(a.Reserved),     // int32
	})
}

func (a OSPFv3) NetcapTimestamp() string {
	return a.Timestamp
}
