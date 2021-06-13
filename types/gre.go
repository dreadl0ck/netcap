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
	"github.com/dreadl0ck/netcap/encoder"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	fieldChecksumPresent   = "ChecksumPresent"
	fieldRoutingPresent    = "RoutingPresent"
	fieldKeyPresent        = "KeyPresent"
	fieldSeqPresent        = "SeqPresent"
	fieldStrictSourceRoute = "StrictSourceRoute"
	fieldAckPresent        = "AckPresent"
	fieldRecursionControl  = "RecursionControl"
	fieldOffset            = "Offset"
	fieldKey               = "Key"
	fieldSeq               = "Seq"
	fieldAck               = "Ack"
	fieldRouting           = "Routing"
)

var fieldsGRE = []string{
	fieldTimestamp,
	fieldChecksumPresent,   // bool
	fieldRoutingPresent,    // bool
	fieldKeyPresent,        // bool
	fieldSeqPresent,        // bool
	fieldStrictSourceRoute, // bool
	fieldAckPresent,        // bool
	fieldRecursionControl,  // int32
	fieldFlags,             // int32
	fieldVersion,           // int32
	fieldProtocol,          // int32
	fieldChecksum,          // int32
	fieldOffset,            // int32
	fieldKey,               // uint32
	fieldSeq,               // uint32
	fieldAck,               // uint32
	fieldRouting,           // *GRERouting
	fieldSrcIP,
	fieldDstIP,
	fieldSrcPort,
	fieldDstPort,
}

// CSVHeader returns the CSV header for the audit record.
func (a *GRE) CSVHeader() []string {
	return filter(fieldsGRE)
}

// CSVRecord returns the CSV record for the audit record.
func (a *GRE) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(a.Timestamp),
		strconv.FormatBool(a.ChecksumPresent),   // bool
		strconv.FormatBool(a.RoutingPresent),    // bool
		strconv.FormatBool(a.KeyPresent),        // bool
		strconv.FormatBool(a.SeqPresent),        // bool
		strconv.FormatBool(a.StrictSourceRoute), // bool
		strconv.FormatBool(a.AckPresent),        // bool
		formatInt32(a.RecursionControl),         // int32
		formatInt32(a.Flags),                    // int32
		formatInt32(a.Version),                  // int32
		formatInt32(a.Protocol),                 // int32
		formatInt32(a.Checksum),                 // int32
		formatInt32(a.Offset),                   // int32
		formatUint32(a.Key),                     // uint32
		formatUint32(a.Seq),                     // uint32
		formatUint32(a.Ack),                     // uint32
		a.Routing.getString(),                   // *GRERouting
		a.SrcIP,
		a.DstIP,
	})
}

// Time returns the timestamp associated with the audit record.
func (a *GRE) Time() int64 {
	return a.Timestamp
}

func (r *GRERouting) getString() string {
	if r == nil {
		return ""
	}

	var b strings.Builder

	b.WriteString(StructureBegin)
	b.WriteString(formatInt32(r.AddressFamily))
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(r.SREOffset))
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(r.SRELength))
	b.WriteString(FieldSeparator)
	b.WriteString(hex.EncodeToString(r.RoutingInformation))
	b.WriteString(FieldSeparator)
	b.WriteString(r.Next.getString())
	b.WriteString(StructureEnd)

	return b.String()
}

// JSON returns the JSON representation of the audit record.
func (a *GRE) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	a.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(a)
}

var greMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_GRE.String()),
		Help: Type_NC_GRE.String() + " audit records",
	},
	fieldsGRE[1:],
)

// Inc increments the metrics for the audit record.
func (a *GRE) Inc() {
	greMetric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (a *GRE) SetPacketContext(ctx *PacketContext) {
	a.SrcIP = ctx.SrcIP
	a.DstIP = ctx.DstIP
}

// Src returns the source address of the audit record.
func (a *GRE) Src() string {
	return a.SrcIP
}

// Dst returns the destination address of the audit record.
func (a *GRE) Dst() string {
	return a.DstIP
}

var greEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (a *GRE) Encode() []string {
	return filter([]string{
		greEncoder.Int64(fieldTimestamp, a.Timestamp),               // int64
		greEncoder.Bool(a.ChecksumPresent),                          // bool
		greEncoder.Bool(a.RoutingPresent),                           // bool
		greEncoder.Bool(a.KeyPresent),                               // bool
		greEncoder.Bool(a.SeqPresent),                               // bool
		greEncoder.Bool(a.StrictSourceRoute),                        // bool
		greEncoder.Bool(a.AckPresent),                               // bool
		greEncoder.Int32(fieldRecursionControl, a.RecursionControl), // int32
		greEncoder.Int32(fieldFlags, a.Flags),                       // int32
		greEncoder.Int32(fieldVersion, a.Version),                   // int32
		greEncoder.Int32(fieldProtocol, a.Protocol),                 // int32
		greEncoder.Int32(fieldChecksum, a.Checksum),                 // int32
		greEncoder.Int32(fieldOffset, a.Offset),                     // int32
		greEncoder.Uint32(fieldKey, a.Key),                          // uint32
		greEncoder.Uint32(fieldSeq, a.Seq),                          // uint32
		greEncoder.Uint32(fieldAck, a.Ack),                          // uint32
		greEncoder.String(fieldRouting, a.Routing.getString()),      // *GRERouting
		dhcp4Encoder.String(fieldSrcIP, a.SrcIP),
		dhcp4Encoder.String(fieldDstIP, a.DstIP),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (a *GRE) Analyze() {}

// NetcapType returns the type of the current audit record
func (a *GRE) NetcapType() Type {
	return Type_NC_GRE
}
