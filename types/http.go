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
	fieldReqContentEncoding,
	fieldResContentEncoding,
	fieldServerName,
}

// CSVHeader returns the CSV header for the audit record.
func (h *HTTP) CSVHeader() []string {
	return filter(fieldsHTTP)
}

// CSVRecord returns the CSV record for the audit record.
func (h *HTTP) CSVRecord() []string {
	var reqCookies []string
	for _, c := range h.ReqCookies {
		reqCookies = append(reqCookies, c.toString())
	}
	var resCookies []string
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
		h.ReqContentEncoding,
		h.ResContentEncoding,
		h.ServerName,
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
		httpEncoder.String(fieldReqContentEncoding, h.ReqContentEncoding),
		httpEncoder.String(fieldResContentEncoding, h.ResContentEncoding),
		httpEncoder.String(fieldServerName, h.ServerName),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (h *HTTP) Analyze() {}

// NetcapType returns the type of the current audit record
func (h *HTTP) NetcapType() Type {
	return Type_NC_HTTP
}
