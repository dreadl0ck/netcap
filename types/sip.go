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
	fieldHeaders        = "Headers"
	fieldIsResponse     = "IsResponse"
	fieldResponseStatus = "ResponseStatus"
)

var fieldsSIP = []string{
	fieldTimestamp,
	fieldVersion,
	fieldMethod,
	fieldHeaders,
	fieldIsResponse,
	fieldResponseCode,
	fieldResponseStatus,
	fieldSrcIP,
	fieldDstIP,
	fieldSrcPort,
	fieldDstPort,
}

// CSVHeader returns the CSV header for the audit record.
func (s *SIP) CSVHeader() []string {
	return filter(fieldsSIP)
}

// CSVRecord returns the CSV record for the audit record.
func (s *SIP) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(s.Timestamp),
		formatInt32(s.Version),           //  int32 `protobuf:"varint,2,opt,name=Version,proto3" json:"Version,omitempty"`
		formatInt32(s.Method),            //   int32 `protobuf:"varint,3,opt,name=Method,proto3" json:"Method,omitempty"`
		join(s.Headers...),               //  []string `protobuf:"bytes,4,rep,name=Headers,proto3" json:"Headers,omitempty"`
		strconv.FormatBool(s.IsResponse), //            bool     `protobuf:"varint,5,opt,name=IsResponse,proto3" json:"IsResponse,omitempty"`
		formatInt32(s.ResponseCode),      //          int32    `protobuf:"varint,6,opt,name=ResponseCode,proto3" json:"ResponseCode,omitempty"`
		s.ResponseStatus,                 //        string   `protobuf
		s.SrcIP,
		s.DstIP,
		formatInt32(s.SrcPort),
		formatInt32(s.DstPort),
	})
}

// Time returns the timestamp associated with the audit record.
func (s *SIP) Time() int64 {
	return s.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (u *SIP) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	u.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(u)
}

var sipMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_SIP.String()),
		Help: Type_NC_SIP.String() + " audit records",
	},
	fieldsSIP[1:],
)

// Inc increments the metrics for the audit record.
func (s *SIP) Inc() {
	sipMetric.WithLabelValues(s.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (s *SIP) SetPacketContext(ctx *PacketContext) {
	s.SrcIP = ctx.SrcIP
	s.DstIP = ctx.DstIP
	s.SrcPort = ctx.SrcPort
	s.DstPort = ctx.DstPort
}

// Src returns the source address of the audit record.
func (s *SIP) Src() string {
	return s.SrcIP
}

// Dst returns the destination address of the audit record.
func (s *SIP) Dst() string {
	return s.DstIP
}

var sipEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (s *SIP) Encode() []string {
	return filter([]string{
		sipEncoder.Int64(fieldTimestamp, s.Timestamp),
		sipEncoder.Int32(fieldVersion, s.Version),                //  int32 `protobuf:"varint,2,opt,name=Version,proto3" json:"Version,omitempty"`
		sipEncoder.Int32(fieldMethod, s.Method),                  //   int32 `protobuf:"varint,3,opt,name=Method,proto3" json:"Method,omitempty"`
		sipEncoder.String(fieldHeaders, join(s.Headers...)),      //  []string `protobuf:"bytes,4,rep,name=Headers,proto3" json:"Headers,omitempty"`
		sipEncoder.Bool(s.IsResponse),                            //            bool     `protobuf:"varint,5,opt,name=IsResponse,proto3" json:"IsResponse,omitempty"`
		sipEncoder.Int32(fieldResponseCode, s.ResponseCode),      //          int32    `protobuf:"varint,6,opt,name=ResponseCode,proto3" json:"ResponseCode,omitempty"`
		sipEncoder.String(fieldResponseStatus, s.ResponseStatus), //        string   `protobuf
		sipEncoder.String(fieldSrcIP, s.SrcIP),
		sipEncoder.String(fieldDstIP, s.DstIP),
		sipEncoder.Int32(fieldSrcPort, s.SrcPort),
		sipEncoder.Int32(fieldDstPort, s.DstPort),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (s *SIP) Analyze() {}

// NetcapType returns the type of the current audit record
func (s *SIP) NetcapType() Type {
	return Type_NC_SIP
}
