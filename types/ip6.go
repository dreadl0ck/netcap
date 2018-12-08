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
	"strconv"
)

func (i IPv6) CSVHeader() []string {
	return filter([]string{
		"Timestamp",
		"Version",        // int32
		"TrafficClass",   // int32
		"FlowLabel",      // uint32
		"Length",         // int32
		"NextHeader",     // int32
		"HopLimit",       // int32
		"SrcIP",          // string
		"DstIP",          // string
		"PayloadEntropy", // float64
		"PayloadSize",    // int32
		"HopByHop",       // *IPv6HopByHop
	})
}

func (i IPv6) CSVRecord() []string {
	var hop string
	if i.HopByHop != nil {
		hop = i.HopByHop.ToString()
	}
	return filter([]string{
		formatTimestamp(i.Timestamp),
		formatInt32(i.Version),      // int32
		formatInt32(i.TrafficClass), // int32
		formatUint32(i.FlowLabel),   // uint32
		formatInt32(i.Length),       // int32
		formatInt32(i.NextHeader),   // int32
		formatInt32(i.HopLimit),     // int32
		i.SrcIP,                     // string
		i.DstIP,                     // string
		strconv.FormatFloat(i.PayloadEntropy, 'f', 6, 64), // float64
		formatInt32(i.PayloadSize),                        // int32
		hop,                                               // *IPv6HopByHop
	})
}

func (i IPv6) NetcapTimestamp() string {
	return i.Timestamp
}

func (h IPv6HopByHop) ToString() string {
	var opts []string
	for _, o := range h.Options {
		opts = append(opts, o.ToString())
	}
	return h.Timestamp + sep + join(opts...)
}
