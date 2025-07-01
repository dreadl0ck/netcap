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
	fieldServiceName      = "ServiceName"
	fieldMessageType      = "MessageType"
	fieldFields           = "Fields"
	fieldRawPayload       = "RawPayload"
	fieldIsValid          = "IsValid"
	fieldErrorMsg         = "ErrorMsg"
	fieldDetectionMethod  = "DetectionMethod"
	fieldFieldTypes       = "FieldTypes"
	fieldMessageCount     = "MessageCount"
)

var fieldsProtobuf = []string{
	fieldTimestamp,
	fieldSrcIP,
	fieldDstIP,
	fieldSrcPort,
	fieldDstPort,
	fieldPayloadSize,
	fieldPayloadEntropy,
	fieldServiceName,
	fieldMessageType,
	fieldIsValid,
	fieldErrorMsg,
	fieldDetectionMethod,
	fieldMessageCount,
}

// CSVHeader returns the CSV header for the audit record.
func (p *Protobuf) CSVHeader() []string {
	return filter(fieldsProtobuf)
}

// CSVRecord returns the CSV record for the audit record.
func (p *Protobuf) CSVRecord() []string {
	var fields []string
	for k, v := range p.Fields {
		fields = append(fields, k+"="+v)
	}
	var fieldTypes []string
	fieldTypes = append(fieldTypes, p.FieldTypes...)

	return filter([]string{
		formatTimestamp(p.Timestamp),
		p.SrcIP,
		p.DstIP,
		formatInt32(p.SrcPort),
		formatInt32(p.DstPort),
		formatInt32(p.PayloadSize),
		formatFloat64(p.PayloadEntropy),
		p.ServiceName,
		p.MessageType,
		strconv.FormatBool(p.IsValid),
		p.ErrorMsg,
		p.DetectionMethod,
		formatInt32(p.MessageCount),
	})
}

// Time returns the timestamp associated with the audit record.
func (p *Protobuf) Time() int64 {
	return p.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (p *Protobuf) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	p.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(p)
}

var protobufMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_Protobuf.String()),
		Help: Type_NC_Protobuf.String() + " audit records",
	},
	fieldsProtobuf[1:],
)

// Inc increments the metrics for the audit record.
func (p *Protobuf) Inc() {
	protobufMetric.WithLabelValues(p.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (p *Protobuf) SetPacketContext(ctx *PacketContext) {
	p.SrcIP = ctx.SrcIP
	p.DstIP = ctx.DstIP
	p.SrcPort = ctx.SrcPort
	p.DstPort = ctx.DstPort
}

// Src returns the source address of the audit record.
func (p *Protobuf) Src() string {
	return p.SrcIP
}

// Dst returns the destination address of the audit record.
func (p *Protobuf) Dst() string {
	return p.DstIP
}

var protobufEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (p *Protobuf) Encode() []string {
	return filter([]string{
		protobufEncoder.Int64(fieldTimestamp, p.Timestamp),
		protobufEncoder.String(fieldSrcIP, p.SrcIP),
		protobufEncoder.String(fieldDstIP, p.DstIP),
		protobufEncoder.Int32(fieldSrcPort, p.SrcPort),
		protobufEncoder.Int32(fieldDstPort, p.DstPort),
		protobufEncoder.Int32(fieldPayloadSize, p.PayloadSize),
		protobufEncoder.Float64(fieldPayloadEntropy, p.PayloadEntropy),
		protobufEncoder.String(fieldServiceName, p.ServiceName),
		protobufEncoder.String(fieldMessageType, p.MessageType),
		protobufEncoder.Bool(p.IsValid),
		protobufEncoder.String(fieldErrorMsg, p.ErrorMsg),
		protobufEncoder.String(fieldDetectionMethod, p.DetectionMethod),
		protobufEncoder.Int32(fieldMessageCount, p.MessageCount),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (p *Protobuf) Analyze() {}

// NetcapType returns the type of the current audit record
func (p *Protobuf) NetcapType() Type {
	return Type_NC_Protobuf
}