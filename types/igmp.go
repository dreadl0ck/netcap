/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017-2020 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
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

	"github.com/prometheus/client_golang/prometheus"
)

var fieldsIGMP = []string{
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
	"SrcIP",
	"DstIP",
}

// CSVHeader returns the CSV header for the audit record.
func (i *IGMP) CSVHeader() []string {
	return filter(fieldsIGMP)
}

// CSVRecord returns the CSV record for the audit record.
func (i *IGMP) CSVRecord() []string {
	var records []string
	for _, r := range i.GroupRecords {
		records = append(records, r.toString())
	}
	// prevent accessing nil pointer
	if i.Context == nil {
		i.Context = &PacketContext{}
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
		join(i.SourceAddresses...),                    // []string
		formatInt32(i.NumberOfGroupRecords),           // int32
		formatInt32(i.NumberOfSources),                // int32
		strings.Join(records, ""),                     // []*IGMPv3GroupRecord
		formatInt32(i.Version),                        // int32
		i.Context.SrcIP,
		i.Context.DstIP,
	})
}

// Time returns the timestamp associated with the audit record.
func (i *IGMP) Time() int64 {
	return i.Timestamp
}

func (i IGMPv3GroupRecord) toString() string {
	var b strings.Builder
	b.WriteString(StructureBegin)
	b.WriteString(formatInt32(i.Type))
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(i.AuxDataLen))
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(i.NumberOfSources))
	b.WriteString(FieldSeparator)
	b.WriteString(i.MulticastAddress)
	b.WriteString(FieldSeparator)
	b.WriteString(join(i.SourceAddresses...))
	b.WriteString(StructureEnd)

	return b.String()
}

// JSON returns the JSON representation of the audit record.
func (i *IGMP) JSON() (string, error) {
	//	i.Timestamp = utils.TimeToUnixMilli(i.Timestamp)
	return jsonMarshaler.MarshalToString(i)
}

var igmpMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_IGMP.String()),
		Help: Type_NC_IGMP.String() + " audit records",
	},
	fieldsIGMP[1:],
)

// Inc increments the metrics for the audit record.
func (i *IGMP) Inc() {
	igmpMetric.WithLabelValues(i.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (i *IGMP) SetPacketContext(ctx *PacketContext) {
	i.Context = ctx
}

// Src returns the source address of the audit record.
func (i *IGMP) Src() string {
	if i.Context != nil {
		return i.Context.SrcIP
	}
	return ""
}

// Dst returns the destination address of the audit record.
func (i *IGMP) Dst() string {
	if i.Context != nil {
		return i.Context.DstIP
	}
	return ""
}
