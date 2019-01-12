/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
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

func (h HTTP) CSVHeader() []string {
	return filter([]string{
		"Timestamp",
		"Proto",
		"Method",
		"Host",
		"UserAgent",
		"Referer",
		"ReqCookies",
		"ReqContentLength",
		"URL",
		"ResContentLength",
		"ContentType",
		"StatusCode",
		"SrcIP",
		"DstIP",
	})
}

func (h HTTP) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(h.Timestamp),
		h.Proto,
		h.Method,
		h.Host,
		h.UserAgent,
		h.Referer,
		join(h.ReqCookies),
		formatInt32(h.ReqContentLength),
		h.URL,
		formatInt32(h.ResContentLength),
		h.ContentType,
		formatInt32(h.StatusCode),
		h.SrcIP,
		h.DstIP,
	})
}

func (f HTTP) NetcapTimestamp() string {
	return f.Timestamp
}
