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

func (d DHCPv4) CSVHeader() []string {
	return filter([]string{
		"Timestamp",    // string
		"Operation",    // int32
		"HardwareType", // int32
		"HardwareLen",  // int32
		"HardwareOpts", // int32
		"Xid",          // uint32
		"Secs",         // int32
		"Flags",        // int32
		"ClientIP",     // string
		"YourClientIP", // string
		"NextServerIP", // string
		"RelayAgentIP", // string
		"ClientHWAddr", // string
		"ServerName",   // []byte
		"File",         // []byte
		"Options",      // []*DHCPOption
	})
}

func (d DHCPv4) CSVRecord() []string {
	var opts []string
	for _, o := range d.Options {
		opts = append(opts, o.ToString())
	}
	return filter([]string{
		formatTimestamp(d.Timestamp),     // string
		formatInt32(d.Operation),         // int32
		formatInt32(d.HardwareType),      // int32
		formatInt32(d.HardwareLen),       // int32
		formatInt32(d.HardwareOpts),      // int32
		formatUint32(d.Xid),              // uint32
		formatInt32(d.Secs),              // int32
		formatInt32(d.Flags),             // int32
		d.ClientIP,                       // string
		d.YourClientIP,                   // string
		d.NextServerIP,                   // string
		d.RelayAgentIP,                   // string
		d.ClientHWAddr,                   // string
		hex.EncodeToString(d.ServerName), // []byte
		hex.EncodeToString(d.File),       // []byte
		strings.Join(opts, ""),           // []*DHCPOption
	})
}

func (d DHCPv4) NetcapTimestamp() string {
	return d.Timestamp
}

func (d DHCPOption) ToString() string {
	var b strings.Builder
	b.WriteString(Begin)
	b.WriteString(formatInt32(d.Type))
	b.WriteString(Separator)
	b.WriteString(formatInt32(d.Length))
	b.WriteString(Separator)
	b.WriteString(hex.EncodeToString(d.Data))
	b.WriteString(End)
	return b.String()
}
