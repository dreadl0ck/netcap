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

func (l LSUpdate) CSVHeader() []string {
	return filter([]string{
		"Timestamp",
		"NumOfLSAs", // uint32
		"LSAs",      // []*LSA
	})
}

func (l LSUpdate) CSVRecord() []string {
	var lsas []string
	for _, v := range l.LSAs {
		lsas = append(lsas, v.ToString())
	}
	return filter([]string{
		formatTimestamp(l.Timestamp),
		formatUint32(l.NumOfLSAs), // uint32
		strings.Join(lsas, "|"),   // []*LSA
	})
}

func (l LSUpdate) NetcapTimestamp() string {
	return l.Timestamp
}

func (l LSA) ToString() string {

	var b strings.Builder

	b.WriteString(begin)
	b.WriteString(formatTimestamp(l.Timestamp)) // string
	b.WriteString(sep)
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
