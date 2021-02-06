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

package http

import (
	"bytes"
	"compress/gzip"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/dreadl0ck/netcap/types"
)

/*
 *	Utils
 */

// set HTTP request on types.HTTP.
func setRequest(h *types.HTTP, req *httpRequest) {
	// set basic info
	h.Timestamp = req.timestamp
	h.Proto = req.request.Proto
	h.Method = req.request.Method
	h.Host = req.request.Host
	h.ReqContentLength = int32(req.request.ContentLength)
	h.ReqContentEncoding = req.request.Header.Get(headerContentEncoding)
	h.ContentType = req.request.Header.Get(headerContentType)
	h.RequestHeader = readHeader(req.request.Header)

	body, err := ioutil.ReadAll(req.request.Body)
	if err == nil {
		h.ContentTypeDetected = http.DetectContentType(body)

		// decompress if required
		if h.ReqContentEncoding == "gzip" {
			r, errReader := gzip.NewReader(bytes.NewReader(body))
			if errReader == nil {
				body, err = ioutil.ReadAll(r)
				if err == nil {
					h.ContentTypeDetected = http.DetectContentType(body)
				}
			}
		}
	}

	// manually replace commas, to avoid breaking them the CSV
	// use the -check flag to validate the generated CSV output and find errors quickly if other fields slipped through
	h.UserAgent = removeCommas(req.request.UserAgent())
	h.Referer = removeCommas(req.request.Referer())
	h.URL = removeCommas(req.request.URL.String())

	// retrieve ip addresses set on the request while processing
	h.SrcIP = req.clientIP
	h.DstIP = req.serverIP

	h.ReqCookies = readCookies(req.request.Cookies())
	h.Parameters = readParameters(req.request.Form)
}

func removeCommas(s string) string {
	return strings.Replace(s, ",", "(comma)", -1)
}

// readCookies transforms an array of *http.Cookie to an array of *types.HTTPCookie.
func readCookies(cookies []*http.Cookie) []*types.HTTPCookie {
	cks := make([]*types.HTTPCookie, 0)

	for _, co := range cookies {
		if co != nil {
			cks = append(cks, &types.HTTPCookie{
				Name:     co.Name,
				Value:    co.Value,
				Path:     co.Path,
				Domain:   co.Domain,
				Expires:  uint64(co.Expires.Unix()),
				MaxAge:   int32(co.MaxAge),
				Secure:   co.Secure,
				HttpOnly: co.HttpOnly,
				SameSite: int32(co.SameSite),
			})
		}
	}

	return cks
}

func newHTTPFromResponse(res *http.Response) *types.HTTP {
	var (
		detected      string
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
		if res.Header.Get(headerContentEncoding) == "gzip" {
			r, errReader := gzip.NewReader(bytes.NewReader(body))
			if errReader == nil {
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
		ResContentType:         res.Header.Get(headerContentType),
		StatusCode:             int32(res.StatusCode),
		ServerName:             res.Header.Get("Server"),
		ResContentEncoding:     res.Header.Get(headerContentEncoding),
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

		// ignore empty params with empty name, they will cause an error in elastic
		if k == " " {
			continue
		}

		// TODO: cleanup this hack to prevent param values with dots breaking the dynamic type mapping of kibana
		v := strings.Join(vals, " ")
		if strings.HasPrefix(v, ".") || strings.HasSuffix(v, ".") {
			v = "'" + v + "'"
		}

		if k == "" {
			k = keyUnknownParam
			// TODO: cleanup this hack to prevent param values with dots breaking the dynamic type mapping of kibana
		} else if strings.HasPrefix(k, ".") || strings.HasSuffix(k, ".") {
			k = "'" + k + "'"
		}

		if strings.Contains(k, ".") {
			k = strings.ReplaceAll(k, ".", "[dot]")
		}

		m[k] = v
	}

	return m
}
