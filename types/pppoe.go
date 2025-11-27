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
	fieldSessionId            = "SessionId"
	fieldCodeName             = "CodeName"
	fieldIsDiscovery          = "IsDiscovery"
	fieldIsSessionTermination = "IsSessionTermination"
	fieldIsSessionEstablished = "IsSessionEstablished"
)

var fieldsPPPoE = []string{
	fieldTimestamp,
	fieldVersion,              // int32
	fieldType,                 // int32
	fieldCode,                 // int32
	fieldCodeName,             // string
	fieldSessionId,            // int32
	fieldLength,               // int32
	fieldIsDiscovery,          // bool
	fieldIsSessionTermination, // bool
	fieldIsSessionEstablished, // bool
}

// CSVHeader returns the CSV header for the audit record.
func (p *PPPoE) CSVHeader() []string {
	return filter(fieldsPPPoE)
}

// CSVRecord returns the CSV record for the audit record.
func (p *PPPoE) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(p.Timestamp),
		formatInt32(p.Version),                     // int32
		formatInt32(p.Type),                        // int32
		formatInt32(p.Code),                        // int32
		p.CodeName,                                 // string
		formatInt32(p.SessionId),                   // int32
		formatInt32(p.Length),                      // int32
		strconv.FormatBool(p.IsDiscovery),          // bool
		strconv.FormatBool(p.IsSessionTermination), // bool
		strconv.FormatBool(p.IsSessionEstablished), // bool
	})
}

// Time returns the timestamp associated with the audit record.
func (p *PPPoE) Time() int64 {
	return p.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (p *PPPoE) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	p.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(p)
}

var pppoeMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_PPPoE.String()),
		Help: Type_NC_PPPoE.String() + " audit records",
	},
	fieldsPPPoE[1:],
)

// Inc increments the metrics for the audit record.
func (p *PPPoE) Inc() {
	pppoeMetric.WithLabelValues(p.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (p *PPPoE) SetPacketContext(*PacketContext) {}

// Src returns the source address of the audit record.
func (p *PPPoE) Src() string {
	return ""
}

// Dst returns the destination address of the audit record.
func (p *PPPoE) Dst() string {
	return ""
}

var pppoeEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (p *PPPoE) Encode() []string {
	return filter([]string{
		pppoeEncoder.Int64(fieldTimestamp, p.Timestamp),
		pppoeEncoder.Int32(fieldVersion, p.Version),     // int32
		pppoeEncoder.Int32(fieldType, p.Type),           // int32
		pppoeEncoder.Int32(fieldCode, p.Code),           // int32
		pppoeEncoder.String(fieldCodeName, p.CodeName),  // string
		pppoeEncoder.Int32(fieldSessionId, p.SessionId), // int32
		pppoeEncoder.Int32(fieldLength, p.Length),       // int32
		pppoeEncoder.Bool(p.IsDiscovery),                // bool
		pppoeEncoder.Bool(p.IsSessionTermination),       // bool
		pppoeEncoder.Bool(p.IsSessionEstablished),       // bool
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (p *PPPoE) Analyze() {}

// NetcapType returns the type of the current audit record
func (p *PPPoE) NetcapType() Type {
	return Type_NC_PPPoE
}

