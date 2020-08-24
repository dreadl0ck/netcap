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
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/dreadl0ck/netcap/utils"
)

var fieldsSIP = []string{
	"Timestamp",
	"Version",
	"Method",
	"Headers",
	"IsResponse",
	"ResponseCode",
	"ResponseStatus",
	"SrcIP",
	"DstIP",
	"SrcPort",
	"DstPort",
}

// CSVHeader returns the CSV header for the audit record.
func (s *SIP) CSVHeader() []string {
	return filter(fieldsSIP)
}

// CSVRecord returns the CSV record for the audit record.
func (s *SIP) CSVRecord() []string {
	// prevent accessing nil pointer
	if s.Context == nil {
		s.Context = &PacketContext{}
	}
	return filter([]string{
		formatTimestamp(s.Timestamp),
		formatInt32(s.Version),           //  int32 `protobuf:"varint,2,opt,name=Version,proto3" json:"Version,omitempty"`
		formatInt32(s.Method),            //   int32 `protobuf:"varint,3,opt,name=Method,proto3" json:"Method,omitempty"`
		join(s.Headers...),               //  []string `protobuf:"bytes,4,rep,name=Headers,proto3" json:"Headers,omitempty"`
		strconv.FormatBool(s.IsResponse), //            bool     `protobuf:"varint,5,opt,name=IsResponse,proto3" json:"IsResponse,omitempty"`
		formatInt32(s.ResponseCode),      //          int32    `protobuf:"varint,6,opt,name=ResponseCode,proto3" json:"ResponseCode,omitempty"`
		s.ResponseStatus,                 //        string   `protobuf
		s.Context.SrcIP,
		s.Context.DstIP,
		s.Context.SrcPort,
		s.Context.DstPort,
	})
}

// Time returns the timestamp associated with the audit record.
func (s *SIP) Time() string {
	return s.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (u *SIP) JSON() (string, error) {
	u.Timestamp = utils.TimeToUnixMilli(u.Timestamp)
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
	s.Context = ctx
}

// Src returns the source address of the audit record.
func (s *SIP) Src() string {
	if s.Context != nil {
		return s.Context.SrcIP
	}
	return ""
}

// Dst returns the destination address of the audit record.
func (s *SIP) Dst() string {
	if s.Context != nil {
		return s.Context.DstIP
	}
	return ""
}
