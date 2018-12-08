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

func (d DHCPv6) CSVHeader() []string {
	return filter([]string{
		"Timestamp",     // string
		"MsgType",       // int32
		"HopCount",      // int32
		"LinkAddr",      // string
		"PeerAddr",      // string
		"TransactionID", // []byte
		"Options",       // []*DHCPv6Option
	})
}

func (d DHCPv6) CSVRecord() []string {
	var opts []string
	for _, o := range d.Options {
		opts = append(opts, o.ToString())
	}
	return filter([]string{
		formatTimestamp(d.Timestamp),        // string
		formatInt32(d.MsgType),              // int32
		formatInt32(d.HopCount),             // int32
		d.LinkAddr,                          // string
		d.PeerAddr,                          // string
		hex.EncodeToString(d.TransactionID), // []byte
		strings.Join(opts, ""),              // []*DHCPv6Option
	})
}

func (d DHCPv6) NetcapTimestamp() string {
	return d.Timestamp
}

func (d DHCPv6Option) ToString() string {
	var b strings.Builder
	b.WriteString(begin)
	b.WriteString(formatInt32(d.Code))
	b.WriteString(sep)
	b.WriteString(formatInt32(d.Length))
	b.WriteString(sep)
	b.WriteString(hex.EncodeToString(d.Data))
	b.WriteString(end)
	return b.String()
}
