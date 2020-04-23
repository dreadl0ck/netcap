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
)

var fieldsHTTP = []string{
	"Timestamp",
	"Proto",
	"Method",
	"Host",
	"UserAgent",
	"Referer",
	"ReqCookies",
	"ResCookies",
	"ReqContentLength",
	"URL",
	"ResContentLength",
	"ContentType",
	"StatusCode",
	"SrcIP",
	"DstIP",
	"ReqContentEncoding",
	"ResContentEncoding",
	"ServerName",
}

func (h HTTP) CSVHeader() []string {
	return filter(fieldsHTTP)
}

func (h HTTP) CSVRecord() []string {
	var reqCookies []string
	for _, c := range h.ReqCookies {
		reqCookies = append(reqCookies, c.ToString())
	}
	var resCookies []string
	for _, c := range h.ResCookies {
		resCookies = append(resCookies, c.ToString())
	}
	return filter([]string{
		formatTimestamp(h.Timestamp),
		h.Proto,
		h.Method,
		h.Host,
		h.UserAgent,
		h.Referer,
		join(reqCookies...),
		join(resCookies...),
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

func (c *HTTPCookie) ToString() string {
	var b strings.Builder

	b.WriteString(Begin)
	b.WriteString(c.Name)
	b.WriteString(Separator)
	b.WriteString(c.Domain)
	b.WriteString(Separator)
	b.WriteString(c.Path)
	b.WriteString(Separator)
	b.WriteString(c.Value)
	b.WriteString(Separator)
	b.WriteString(formatUint64(c.Expires))
	b.WriteString(Separator)
	b.WriteString(strconv.FormatBool(c.HttpOnly))
	b.WriteString(Separator)
	b.WriteString(formatInt32(c.MaxAge))
	b.WriteString(Separator)
	b.WriteString(formatInt32(c.SameSite))
	b.WriteString(Separator)
	b.WriteString(strconv.FormatBool(c.Secure))
	b.WriteString(End)

	return b.String()
}

func (f HTTP) Time() string {
	return f.Timestamp
}

func (a HTTP) JSON() (string, error) {
	return jsonMarshaler.MarshalToString(&a)
}

var httpMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_HTTP.String()),
		Help: Type_NC_HTTP.String() + " audit records",
	},
	fieldsHTTP[1:],
)

func init() {
	prometheus.MustRegister(httpMetric)
}

func (a HTTP) Inc() {
	httpMetric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

func (a *HTTP) SetPacketContext(ctx *PacketContext) {}

func (a HTTP) Src() string {
	return a.SrcIP
}

func (a HTTP) Dst() string {
	return a.DstIP
}
