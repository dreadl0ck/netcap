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
	fieldMethod             = "Method"
	fieldHost               = "Host"
	fieldUserAgent          = "UserAgent"
	fieldReferer            = "Referer"
	fieldReqCookies         = "ReqCookies"
	fieldResCookies         = "ResCookies"
	fieldReqContentLength   = "ReqContentLength"
	fieldURL                = "URL"
	fieldResContentLength   = "ResContentLength"
	fieldStatusCode         = "StatusCode"
	fieldReqContentEncoding = "ReqContentEncoding"
	fieldResContentEncoding = "ResContentEncoding"
	fieldJa4h               = "Ja4h"
	// fieldFlow, fieldSrcPort, fieldDstPort are defined in other type files
)

var fieldsHTTP = []string{
	fieldTimestamp,
	fieldProto,
	fieldMethod,
	fieldHost,
	fieldUserAgent,
	fieldReferer,
	//fieldReqCookies,
	//fieldResCookies,
	fieldReqContentLength,
	fieldURL,
	fieldResContentLength,
	fieldContentType,
	fieldStatusCode,
	fieldSrcIP,
	fieldDstIP,
	fieldSrcPort,
	fieldDstPort,
	fieldReqContentEncoding,
	fieldResContentEncoding,
	fieldServerName,
	fieldFlow,
	fieldJa4h,
}

// CSVHeader returns the CSV header for the audit record.
func (h *HTTP) CSVHeader() []string {
	return filter(fieldsHTTP)
}

// CSVRecord returns the CSV record for the audit record.
func (h *HTTP) CSVRecord() []string {
	reqCookies := make([]string, 0, len(h.ReqCookies))
	for _, c := range h.ReqCookies {
		reqCookies = append(reqCookies, c.toString())
	}
	resCookies := make([]string, 0, len(h.ResCookies))
	for _, c := range h.ResCookies {
		resCookies = append(resCookies, c.toString())
	}
	return filter([]string{
		formatTimestamp(h.Timestamp),
		h.Proto,
		h.Method,
		h.Host,
		h.UserAgent,
		h.Referer,
		//join(reqCookies...),
		//join(resCookies...),
		formatInt32(h.ReqContentLength),
		h.URL,
		formatInt32(h.ResContentLength),
		h.ContentType,
		formatInt32(h.StatusCode),
		h.SrcIP,
		h.DstIP,
		formatInt32(h.SrcPort),
		formatInt32(h.DstPort),
		h.ReqContentEncoding,
		h.ResContentEncoding,
		h.ServerName,
		h.Flow,
		h.Ja4H,
	})
}

func (c *HTTPCookie) toString() string {
	var b strings.Builder

	b.WriteString(StructureBegin)
	b.WriteString(c.Name)
	b.WriteString(FieldSeparator)
	b.WriteString(c.Domain)
	b.WriteString(FieldSeparator)
	b.WriteString(c.Path)
	b.WriteString(FieldSeparator)
	b.WriteString(c.Value)
	b.WriteString(FieldSeparator)
	b.WriteString(formatUint64(c.Expires))
	b.WriteString(FieldSeparator)
	b.WriteString(strconv.FormatBool(c.HttpOnly))
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(c.MaxAge))
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(c.SameSite))
	b.WriteString(FieldSeparator)
	b.WriteString(strconv.FormatBool(c.Secure))
	b.WriteString(StructureEnd)

	return b.String()
}

// Time returns the timestamp associated with the audit record.
func (h *HTTP) Time() int64 {
	return h.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (h *HTTP) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	h.Timestamp /= int64(time.Millisecond)

	h.RequestBody = nil  // TODO: dont kill elastic
	h.ResponseBody = nil // TODO: dont kill elastic
	return jsonMarshaler.MarshalToString(h)
}

var httpMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_HTTP.String()),
		Help: Type_NC_HTTP.String() + " audit records",
	},
	fieldsHTTP[1:],
)

// Inc increments the metrics for the audit record.
func (h *HTTP) Inc() {
	httpMetric.WithLabelValues(h.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (h *HTTP) SetPacketContext(*PacketContext) {}

// Src returns the source address of the audit record.
func (h *HTTP) Src() string {
	return h.SrcIP
}

// Dst returns the destination address of the audit record.
func (h *HTTP) Dst() string {
	return h.DstIP
}

var httpEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (h *HTTP) Encode() []string {
	return filter([]string{
		httpEncoder.Int64(fieldTimestamp, h.Timestamp),
		httpEncoder.String(fieldProto, h.Proto),
		httpEncoder.String(fieldMethod, h.Method),
		httpEncoder.String(fieldHost, h.Host),
		httpEncoder.String(fieldUserAgent, h.UserAgent),
		httpEncoder.String(fieldReferer, h.Referer),
		// TODO: flatten
		//join(reqCookies...),
		//join(resCookies...),
		httpEncoder.Int32(fieldReqContentLength, h.ReqContentLength),
		httpEncoder.String(fieldURL, h.URL),
		httpEncoder.Int32(fieldResContentLength, h.ResContentLength),
		httpEncoder.String(fieldContentType, h.ContentType),
		httpEncoder.Int32(fieldStatusCode, h.StatusCode),
		httpEncoder.String(fieldSrcIP, h.SrcIP),
		httpEncoder.String(fieldDstIP, h.DstIP),
		httpEncoder.Int32(fieldSrcPort, h.SrcPort),
		httpEncoder.Int32(fieldDstPort, h.DstPort),
		httpEncoder.String(fieldReqContentEncoding, h.ReqContentEncoding),
		httpEncoder.String(fieldResContentEncoding, h.ResContentEncoding),
		httpEncoder.String(fieldServerName, h.ServerName),
		httpEncoder.String(fieldFlow, h.Flow),
		httpEncoder.String(fieldJa4h, h.Ja4H),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (h *HTTP) Analyze() {}

// NetcapType returns the type of the current audit record
func (h *HTTP) NetcapType() Type {
	return Type_NC_HTTP
}
