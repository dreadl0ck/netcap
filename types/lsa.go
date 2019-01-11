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

func (l LSA) CSVHeader() []string {
	return filter([]string{
		"Timestamp",
		"LSAge",       // int32
		"LSType",      // int32
		"LinkStateID", // uint32
		"AdvRouter",   // uint32
		"LSSeqNumber", // uint32
		"LSChecksum",  // int32
		"Length",      // int32
		"LSOptions",   // int32
	})
}

func (l LSA) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(l.Timestamp),
		formatInt32(l.LSAge),        // int32
		formatInt32(l.LSType),       // int32
		formatUint32(l.LinkStateID), // uint32
		formatUint32(l.AdvRouter),   // uint32
		formatUint32(l.LSSeqNumber), // uint32
		formatInt32(l.LSChecksum),   // int32
		formatInt32(l.Length),       // int32
		formatInt32(l.LSOptions),    // int32
	})
}

func (l LSA) NetcapTimestamp() string {
	return l.Timestamp
}
