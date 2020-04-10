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

package encoder

import (
	"bytes"
	"compress/gzip"
	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/netcap/types"
	"github.com/golang/protobuf/proto"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

var httpEncoder = CreateCustomEncoder(types.Type_NC_HTTP, "HTTP", func(d *CustomEncoder) error {
	streamFactory.decodeHTTP = true
	return nil
}, func(packet gopacket.Packet) proto.Message {
	return nil
}, func(e *CustomEncoder) error {
	return nil
})

/*
 *	Utils
 */

// set HTTP request on types.HTTP
func setRequest(h *types.HTTP, req *http.Request) {

	// set basic info
	h.Timestamp = req.Header.Get("netcap-ts")
	h.Proto = req.Proto
	h.Method = req.Method
	h.Host = req.Host
	h.ReqContentLength = int32(req.ContentLength)
	h.ReqContentEncoding = req.Header.Get("Content-Encoding")
	h.ContentType = req.Header.Get("Content-Type")
	h.RequestHeader = readHeader(req.Header)

	body, err := ioutil.ReadAll(req.Body)
	if err == nil {
		h.ContentTypeDetected = http.DetectContentType(body)

		// decompress if required
		if h.ReqContentEncoding == "gzip" {
			r, err := gzip.NewReader(bytes.NewReader(body))
			if err == nil {
				body, err = ioutil.ReadAll(r)
				if err == nil {
					h.ContentTypeDetected = http.DetectContentType(body)
				}
			}
		}
	}

	// manually replace commas, to avoid breaking them the CSV
	// use the -check flag to validate the generated CSV output and find errors quickly
	h.UserAgent = strings.Replace(req.UserAgent(), ",", "(comma)", -1)
	h.Referer = strings.Replace(req.Referer(), ",", "(comma)", -1)
	h.URL = strings.Replace(req.URL.String(), ",", "(comma)", -1)

	// retrieve ip addresses set on the request while processing
	h.SrcIP = req.Header.Get("netcap-clientip")
	h.DstIP = req.Header.Get("netcap-serverip")

	h.ReqCookies = readCookies(req.Cookies())
	h.Parameters = readParameters(req.Form)
}

func readCookies(cookies []*http.Cookie) []*types.HTTPCookie {
	var cks = make([]*types.HTTPCookie, 0)
	for _, c := range cookies {
		if c != nil {
			cks = append(cks, &types.HTTPCookie{
				Name:     c.Name,
				Value:    c.Value,
				Path:     c.Path,
				Domain:   c.Domain,
				Expires:  uint64(c.Expires.Unix()),
				MaxAge:   int32(c.MaxAge),
				Secure:   c.Secure,
				HttpOnly: c.HttpOnly,
				SameSite: int32(c.SameSite),
			})
		}
	}
	return cks
}

func newHTTPFromResponse(res *http.Response) *types.HTTP {

	var (
		detected string
		contentLength = int32(res.ContentLength)
	)

	// read body data
	body, err := ioutil.ReadAll(res.Body)
	if err == nil {

		if contentLength == -1 {
			// determine length manually
			contentLength = int32(len(body))
		}

		// decompress payload if required
		if res.Header.Get("Content-Encoding") == "gzip" {
			r, err := gzip.NewReader(bytes.NewReader(body))
			if err == nil {
				body, err = ioutil.ReadAll(r)
				if err == nil {
					detected = http.DetectContentType(body)
				}
			}
		} else {
			detected = http.DetectContentType(body)
		}
	}

	return &types.HTTP{
		ResContentLength:       contentLength,
		ResContentType:         res.Header.Get("Content-Type"),
		StatusCode:             int32(res.StatusCode),
		ServerName:             res.Header.Get("Server"),
		ResContentEncoding:     res.Header.Get("Content-Encoding"),
		ResContentTypeDetected: detected,
		ResCookies:             readCookies(res.Cookies()),
		ResponseHeader:         readHeader(res.Header),
	}
}

func readHeader(h http.Header) map[string]string {
	m := make(map[string]string)
	for k, vals := range h {
		m[k] = strings.Join(vals, " ")
	}
	return m
}

func readParameters(h url.Values) map[string]string {
	m := make(map[string]string)
	for k, vals := range h {
		m[k] = strings.Join(vals, " ")
	}
	return m
}