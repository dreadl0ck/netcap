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
	"strconv"
	"strings"
)

func (i IGMP) CSVHeader() []string {
	return filter([]string{
		"Timestamp",
		"Type",                    // int32
		"MaxResponseTime",         // uint64
		"Checksum",                // int32
		"GroupAddress",            // []byte
		"SupressRouterProcessing", // bool
		"RobustnessValue",         // int32
		"IntervalTime",            // uint64
		"SourceAddresses",         // []string
		"NumberOfGroupRecords",    // int32
		"NumberOfSources",         // int32
		"GroupRecords",            // []*IGMPv3GroupRecord
		"Version",                 // int32
	})
}

func (i IGMP) CSVRecord() []string {
	var records []string
	for _, r := range i.GroupRecords {
		records = append(records, r.ToString())
	}
	return filter([]string{
		formatTimestamp(i.Timestamp),
		formatInt32(i.Type),                           // int32
		formatUint64(i.MaxResponseTime),               // uint64
		formatInt32(i.Checksum),                       // int32
		hex.EncodeToString(i.GroupAddress),            // []byte
		strconv.FormatBool(i.SupressRouterProcessing), // bool
		formatInt32(i.RobustnessValue),                // int32
		formatUint64(i.IntervalTime),                  // uint64
		strings.Join(i.SourceAddresses, "/"),          // []string
		formatInt32(i.NumberOfGroupRecords),           // int32
		formatInt32(i.NumberOfSources),                // int32
		strings.Join(records, ""),                     // []*IGMPv3GroupRecord
		formatInt32(i.Version),                        // int32
	})
}

func (i IGMP) NetcapTimestamp() string {
	return i.Timestamp
}

func (i IGMPv3GroupRecord) ToString() string {

	var b strings.Builder
	b.WriteString(begin)
	b.WriteString(formatInt32(i.Type))
	b.WriteString(sep)
	b.WriteString(formatInt32(i.AuxDataLen))
	b.WriteString(sep)
	b.WriteString(formatInt32(i.NumberOfSources))
	b.WriteString(sep)
	b.WriteString(i.MulticastAddress)
	b.WriteString(sep)
	b.WriteString(strings.Join(i.SourceAddresses, "/"))
	b.WriteString(end)

	return b.String()
}
