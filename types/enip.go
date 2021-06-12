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
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	fieldCommand         = "Command"
	fieldSessionHandle   = "SessionHandle"
	fieldSenderContext   = "SenderContext"
	fieldCommandSpecific = "CommandSpecific"
)

var fieldsENIP = []string{
	fieldTimestamp,
	fieldCommand,       // uint32
	fieldLength,        // uint32
	fieldSessionHandle, // uint32
	fieldStatus,        // uint32
	fieldSenderContext, // []byte
	fieldOptions,       // uint32
	//fieldCommandSpecific, // *ENIPCommandSpecificData
	fieldSrcIP,
	fieldDstIP,
	fieldSrcPort,
	fieldDstPort,
}

// CSVHeader returns the CSV header for the audit record.
func (en *ENIP) CSVHeader() []string {
	return filter(fieldsENIP)
}

// CSVRecord returns the CSV record for the audit record.
func (en *ENIP) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(en.Timestamp),
		formatUint32(en.Command),             // uint32
		formatUint32(en.Length),              // uint32
		formatUint32(en.SessionHandle),       // uint32
		formatUint32(en.Status),              // uint32
		hex.EncodeToString(en.SenderContext), // []byte
		formatUint32(en.Options),             // uint32
		// TODO: flatten
		//en.CommandSpecific.String(),          // *ENIPCommandSpecificData
		en.SrcIP,
		en.DstIP,
		formatInt32(en.SrcPort),
		formatInt32(en.DstPort),
	})
}

// Time returns the timestamp associated with the audit record.
func (en *ENIP) Time() int64 {
	return en.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (en *ENIP) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	en.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(en)
}

var enipMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_ENIP.String()),
		Help: Type_NC_ENIP.String() + " audit records",
	},
	fieldsENIP[1:],
)

// Inc increments the metrics for the audit record.
func (en *ENIP) Inc() {
	enipMetric.WithLabelValues(en.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (en *ENIP) SetPacketContext(ctx *PacketContext) {
	en.SrcIP = ctx.SrcIP
	en.DstIP = ctx.DstIP
	en.SrcPort = ctx.SrcPort
	en.DstPort = ctx.DstPort
}

// Src returns the source address of the audit record.
func (en *ENIP) Src() string {
	return en.SrcIP
}

// Dst returns the destination address of the audit record.
func (en *ENIP) Dst() string {
	return en.DstIP
}

var enipEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (en *ENIP) Encode() []string {
	return filter([]string{
		enipEncoder.Int64(fieldTimestamp, en.Timestamp),
		enipEncoder.Uint32(fieldCommand, en.Command),                                 // uint32
		enipEncoder.Uint32(fieldLength, en.Length),                                   // uint32
		enipEncoder.Uint32(fieldSessionHandle, en.SessionHandle),                     // uint32
		enipEncoder.Uint32(fieldStatus, en.Status),                                   // uint32
		enipEncoder.String(fieldSenderContext, hex.EncodeToString(en.SenderContext)), // []byte
		enipEncoder.Uint32(fieldOptions, en.Options),                                 // uint32
		// TODO: flatten
		//en.CommandSpecific.String(),          // *ENIPCommandSpecificData
		enipEncoder.String(fieldSrcIP, en.SrcIP),
		enipEncoder.String(fieldDstIP, en.DstIP),
		enipEncoder.Int32(fieldSrcPort, en.SrcPort),
		enipEncoder.Int32(fieldDstPort, en.DstPort),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (en *ENIP) Analyze() {}

// NetcapType returns the type of the current audit record
func (a *ENIP) NetcapType() Type {
	return Type_NC_ENIP
}
