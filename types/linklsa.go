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

func (l LinkLSA) CSVHeader() []string {
	return filter([]string{
		"Timestamp",
		"RtrPriority",      //  int32
		"Options",          //  uint32
		"LinkLocalAddress", //  []byte
		"NumOfPrefixes",    //  uint32
		"Prefixes",         //  []*LSAPrefix
	})
}

func (l LinkLSA) CSVRecord() []string {
	var prefixes []string
	for _, v := range l.Prefixes {
		prefixes = append(prefixes, v.ToString())
	}
	return filter([]string{
		formatTimestamp(l.Timestamp),
		formatInt32(l.RtrPriority),             //  int32
		formatUint32(l.Options),                //  uint32
		hex.EncodeToString(l.LinkLocalAddress), //  []byte
		formatUint32(l.NumOfPrefixes),          //  uint32
		strings.Join(prefixes, "|"),            //  []*LSAPrefix
	})
}

func (l LinkLSA) NetcapTimestamp() string {
	return l.Timestamp
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
