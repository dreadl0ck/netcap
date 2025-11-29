/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package types

import (
	"strconv"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/encoder"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	fieldHeaders        = "Headers"
	fieldIsResponse     = "IsResponse"
	fieldResponseStatus = "ResponseStatus"
	// SIP-specific security fields (only constants not defined elsewhere)
	fieldMethodName          = "MethodName"
	fieldCallID              = "CallID"
	fieldContact             = "Contact"
	fieldContentLength       = "ContentLength"
	fieldVia                 = "Via"
	fieldCSeq                = "CSeq"
	fieldCSeqNumber          = "CSeqNumber"
	fieldCSeqMethod          = "CSeqMethod"
	fieldRequestURI          = "RequestURI"
	fieldMaxForwards         = "MaxForwards"
	fieldAuthorization       = "Authorization"
	fieldHasKnownAttackTool  = "HasKnownAttackTool"
	fieldHasViaSpoofing      = "HasViaSpoofing"
	fieldHasOversizedHeaders = "HasOversizedHeaders"
	fieldHasSDPPrivateIPLeak = "HasSDPPrivateIPLeak"
	fieldSDPConnectionIP     = "SDPConnectionIP"
	fieldSDPMediaType        = "SDPMediaType"
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
	// Security monitoring fields
	fieldMethodName,
	fieldCallID,
	fieldFrom,
	fieldTo,
	fieldContact,
	fieldUserAgent,
	fieldContentType,
	fieldContentLength,
	fieldVia,
	fieldCSeq,
	fieldCSeqNumber,
	fieldCSeqMethod,
	fieldRequestURI,
	fieldMaxForwards,
	fieldAuthorization,
	// Security analysis fields
	fieldIsAnomalous,
	fieldAnomalyReason,
	fieldRiskScore,
	fieldRiskFactors,
	fieldHasKnownAttackTool,
	fieldHasViaSpoofing,
	fieldHasOversizedHeaders,
	fieldHasSDPPrivateIPLeak,
	fieldSDPConnectionIP,
	fieldSDPMediaType,
}

// CSVHeader returns the CSV header for the audit record.
func (s *SIP) CSVHeader() []string {
	return filter(fieldsSIP)
}

// CSVRecord returns the CSV record for the audit record.
func (s *SIP) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(s.Timestamp),
		formatInt32(s.Version),
		formatInt32(s.Method),
		join(s.Headers...),
		strconv.FormatBool(s.IsResponse),
		formatInt32(s.ResponseCode),
		s.ResponseStatus,
		s.SrcIP,
		s.DstIP,
		formatInt32(s.SrcPort),
		formatInt32(s.DstPort),
		// Security monitoring fields
		s.MethodName,
		s.CallID,
		s.From,
		s.To,
		s.Contact,
		s.UserAgent,
		s.ContentType,
		formatInt32(s.ContentLength),
		s.Via,
		s.CSeq,
		formatInt32(s.CSeqNumber),
		s.CSeqMethod,
		s.RequestURI,
		formatInt32(s.MaxForwards),
		s.Authorization,
		// Security analysis fields
		strconv.FormatBool(s.IsAnomalous),
		s.AnomalyReason,
		formatInt32(s.RiskScore),
		join(s.RiskFactors...),
		strconv.FormatBool(s.HasKnownAttackTool),
		strconv.FormatBool(s.HasViaSpoofing),
		strconv.FormatBool(s.HasOversizedHeaders),
		strconv.FormatBool(s.HasSDPPrivateIPLeak),
		s.SDPConnectionIP,
		s.SDPMediaType,
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
		sipEncoder.Int32(fieldVersion, s.Version),
		sipEncoder.Int32(fieldMethod, s.Method),
		sipEncoder.String(fieldHeaders, join(s.Headers...)),
		sipEncoder.Bool(s.IsResponse),
		sipEncoder.Int32(fieldResponseCode, s.ResponseCode),
		sipEncoder.String(fieldResponseStatus, s.ResponseStatus),
		sipEncoder.String(fieldSrcIP, s.SrcIP),
		sipEncoder.String(fieldDstIP, s.DstIP),
		sipEncoder.Int32(fieldSrcPort, s.SrcPort),
		sipEncoder.Int32(fieldDstPort, s.DstPort),
		// Security monitoring fields
		sipEncoder.String(fieldMethodName, s.MethodName),
		sipEncoder.String(fieldCallID, s.CallID),
		sipEncoder.String(fieldFrom, s.From),
		sipEncoder.String(fieldTo, s.To),
		sipEncoder.String(fieldContact, s.Contact),
		sipEncoder.String(fieldUserAgent, s.UserAgent),
		sipEncoder.String(fieldContentType, s.ContentType),
		sipEncoder.Int32(fieldContentLength, s.ContentLength),
		sipEncoder.String(fieldVia, s.Via),
		sipEncoder.String(fieldCSeq, s.CSeq),
		sipEncoder.Int32(fieldCSeqNumber, s.CSeqNumber),
		sipEncoder.String(fieldCSeqMethod, s.CSeqMethod),
		sipEncoder.String(fieldRequestURI, s.RequestURI),
		sipEncoder.Int32(fieldMaxForwards, s.MaxForwards),
		sipEncoder.String(fieldAuthorization, s.Authorization),
		// Security analysis fields
		sipEncoder.Bool(s.IsAnomalous),
		sipEncoder.String(fieldAnomalyReason, s.AnomalyReason),
		sipEncoder.Int32(fieldRiskScore, s.RiskScore),
		sipEncoder.String(fieldRiskFactors, join(s.RiskFactors...)),
		sipEncoder.Bool(s.HasKnownAttackTool),
		sipEncoder.Bool(s.HasViaSpoofing),
		sipEncoder.Bool(s.HasOversizedHeaders),
		sipEncoder.Bool(s.HasSDPPrivateIPLeak),
		sipEncoder.String(fieldSDPConnectionIP, s.SDPConnectionIP),
		sipEncoder.String(fieldSDPMediaType, s.SDPMediaType),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (s *SIP) Analyze() {}

// NetcapType returns the type of the current audit record
func (s *SIP) NetcapType() Type {
	return Type_NC_SIP
}
