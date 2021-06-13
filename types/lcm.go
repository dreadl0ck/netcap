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
	"github.com/dreadl0ck/netcap/encoder"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	fieldMagic          = "Magic"
	fieldTotalFragments = "TotalFragments"
	fieldChannelName    = "ChannelName"
	fieldFragmented     = "Fragmented"
)

var fieldsLCM = []string{
	fieldTimestamp,
	fieldMagic,          // int32
	fieldSequenceNumber, // int32
	fieldPayloadSize,    // int32
	fieldFragmentOffset, // int32
	fieldFragmentNumber, // int32
	fieldTotalFragments, // int32
	fieldChannelName,    // string
	fieldFragmented,     // bool
	fieldSrcIP,
	fieldDstIP,
	fieldSrcPort,
	fieldDstPort,
}

// CSVHeader returns the CSV header for the audit record.
func (a *LCM) CSVHeader() []string {
	return filter(fieldsLCM)
}

// CSVRecord returns the CSV record for the audit record.
func (a *LCM) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(a.Timestamp),
		formatInt32(a.Magic),             // int32
		formatInt32(a.SequenceNumber),    // int32
		formatInt32(a.PayloadSize),       // int32
		formatInt32(a.FragmentOffset),    // int32
		formatInt32(a.FragmentNumber),    // int32
		formatInt32(a.TotalFragments),    // int32
		a.ChannelName,                    // string
		strconv.FormatBool(a.Fragmented), // bool
		a.SrcIP,
		a.DstIP,
		formatInt32(a.SrcPort),
		formatInt32(a.DstPort),
	})
}

// Time returns the timestamp associated with the audit record.
func (a *LCM) Time() int64 {
	return a.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (a *LCM) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	a.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(a)
}

var lcmMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_LCM.String()),
		Help: Type_NC_LCM.String() + " audit records",
	},
	fieldsLCM[1:],
)

// Inc increments the metrics for the audit record.
func (a *LCM) Inc() {
	lcmMetric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (a *LCM) SetPacketContext(ctx *PacketContext) {
	a.SrcIP = ctx.SrcIP
	a.DstIP = ctx.DstIP
	a.SrcPort = ctx.SrcPort
	a.DstPort = ctx.DstPort
}

// Src returns the source address of the audit record.
func (a *LCM) Src() string {
	return a.SrcIP
}

// Dst returns the destination address of the audit record.
func (a *LCM) Dst() string {
	return a.DstIP
}

var lcmEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (a *LCM) Encode() []string {
	return filter([]string{
		lcmEncoder.Int64(fieldTimestamp, a.Timestamp),
		lcmEncoder.Int32(fieldMagic, a.Magic),                   // int32
		lcmEncoder.Int32(fieldSequenceNumber, a.SequenceNumber), // int32
		lcmEncoder.Int32(fieldPayloadSize, a.PayloadSize),       // int32
		lcmEncoder.Int32(fieldFragmentOffset, a.FragmentOffset), // int32
		lcmEncoder.Int32(fieldFragmentNumber, a.FragmentNumber), // int32
		lcmEncoder.Int32(fieldTotalFragments, a.TotalFragments), // int32
		lcmEncoder.String(fieldChannelName, a.ChannelName),      // string
		lcmEncoder.Bool(a.Fragmented),                           // bool
		lcmEncoder.String(fieldSrcIP, a.SrcIP),
		lcmEncoder.String(fieldDstIP, a.DstIP),
		lcmEncoder.Int32(fieldSrcPort, a.SrcPort),
		lcmEncoder.Int32(fieldDstPort, a.DstPort),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (a *LCM) Analyze() {}

// NetcapType returns the type of the current audit record
func (a *LCM) NetcapType() Type {
	return Type_NC_LCM
}
