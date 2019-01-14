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

func (l IPv6HopByHop) CSVHeader() []string {
	return filter([]string{
		"Timestamp",
		"Options",
	})
}

func (l IPv6HopByHop) CSVRecord() []string {
	opts := make([]string, len(l.Options))
	for i, v := range l.Options {
		opts[i] = v.ToString()
	}
	return filter([]string{
		formatTimestamp(l.Timestamp),
		strings.Join(opts, ""),
	})
}

func (l IPv6HopByHop) NetcapTimestamp() string {
	return l.Timestamp
}

func (o IPv6HopByHopOption) ToString() string {
	var b strings.Builder
	b.WriteString(Begin)
	b.WriteString(formatInt32(o.OptionType))        // int32
	b.WriteString(formatInt32(o.OptionLength))      // int32
	b.WriteString(formatInt32(o.ActualLength))      // int32
	b.WriteString(hex.EncodeToString(o.OptionData)) // []byte
	b.WriteString(o.OptionAlignment.ToString())     //  *IPv6HopByHopOptionAlignment
	b.WriteString(End)
	return b.String()
}

func (a IPv6HopByHopOptionAlignment) ToString() string {
	return join(formatInt32(a.One), formatInt32(a.Two))
}
