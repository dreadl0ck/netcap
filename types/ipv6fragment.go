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

import "strconv"

func (a IPv6Fragment) CSVHeader() []string {
	return filter([]string{
		"Timestamp",
		"NextHeader",
		"Reserved1",
		"FragmentOffset",
		"Reserved2",
		"MoreFragments",
		"Identification",
	})
}

func (a IPv6Fragment) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(a.Timestamp),
		formatInt32(a.NextHeader),           // int32
		formatInt32(a.Reserved1),            // int32
		formatInt32(a.FragmentOffset),       // int32
		formatInt32(a.Reserved2),            // int32
		strconv.FormatBool(a.MoreFragments), // bool
		formatUint32(a.Identification),      // uint32
	})
}

func (a IPv6Fragment) NetcapTimestamp() string {
	return a.Timestamp
}

func (a IPv6Fragment) JSON() (string, error) {
	return jsonMarshaler.MarshalToString(&a)
}
