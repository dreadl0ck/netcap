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

package http

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/url"
	"strings"

	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/file"
	ja4 "github.com/dreadl0ck/netcap/internal/ja4plusadapter"
	"github.com/dreadl0ck/netcap/internal/resolvers"
	"github.com/dreadl0ck/netcap/types"
)

/*
 *	Utils
 */

// set HTTP request on types.HTTP.
func setRequest(h *types.HTTP, req *httpRequest) {
	if req.incomplete {
		addStatus(h, "incomplete_request_body")
	}
	h.RawRequestLine, h.RequestHeaders = req.evidence.line, req.evidence.headers
	h.ParseQualifications = appendUnique(h.ParseQualifications, req.evidence.issues...)
	for _, issue := range req.evidence.issues {
		addStatus(h, issue)
	}
	// set basic info
	h.Timestamp = req.timestamp
	h.Proto = req.request.Proto
	h.Method = req.request.Method
	h.Host = req.request.Host
	h.ReqContentLength = int32(req.request.ContentLength)
	h.ReqContentEncoding = req.request.Header.Get(headerContentEncoding)
	h.ContentType = req.request.Header.Get(headerContentType)
	h.RequestHeader = readHeader(req.request.Header)

	body := req.body
	var err error
	if !req.bodyLoaded {
		var release func()
		body, release, err = file.ReadBody(req.request.Body)
		defer release()
	}
	req.request.Body = io.NopCloser(bytes.NewReader(body))
	if decoderconfig.Instance != nil && decoderconfig.Instance.IncludePayloads {
		h.RequestBody = body
	}
	if err == nil && !req.evidence.unsafe {
		h.ContentTypeDetected = http.DetectContentType(body)

		// decompress if required
		if h.ReqContentEncoding == "gzip" {
			r, errReader := gzip.NewReader(bytes.NewReader(body))
			if errReader == nil {
				var releaseDecoded func()
				body, releaseDecoded, err = file.ReadBody(r)
				defer releaseDecoded()
				_ = r.Close()
				if err == nil {
					h.ContentTypeDetected = http.DetectContentType(body)
				}
			}
		}
	}

	h.UserAgent = req.request.UserAgent()
	h.Referer = req.request.Referer()
	h.URL = req.request.RequestURI

	// retrieve ip addresses and ports set on the request while processing
	h.SrcIP = req.clientIP
	h.DstIP = req.serverIP
	h.SrcPort = req.clientPort
	h.DstPort = req.serverPort
	h.Flow = req.flow

	h.ReqCookies = readCookies(req.request.Cookies())
	h.Parameters = readParameters(req.request.Form)

	// Security-relevant request headers
	h.AuthorizationType = extractAuthType(req.request.Header.Get("Authorization"))
	h.XForwardedFor = req.request.Header.Get("X-Forwarded-For")
	h.XRealIP = req.request.Header.Get("X-Real-IP")

	// JA4H HTTP client fingerprinting
	// Compute JA4H fingerprint if we have header order
	if ja4.Enabled && len(req.headerOrder) > 0 {
		ja4hData := &ja4.HTTPData{
			Method:         req.request.Method,
			Version:        req.request.Proto,
			HeaderOrder:    req.headerOrder,
			HasCookie:      len(req.request.Cookies()) > 0,
			CookieFields:   req.cookieFields,
			AcceptLanguage: req.acceptLang,
		}
		h.Ja4H = ja4.ComputeJA4H(ja4hData)
		// Lookup JA4H fingerprint in database for enrichment
		h.Ja4HDescription = resolvers.LookupJA4H(h.Ja4H)
	}
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
	body, release, err := file.ReadBody(res.Body)
	defer release()
	if err == nil {

		if contentLength == -1 {
			// determine length manually
			contentLength = int32(len(body))
		}

		// decompress payload if required
		if res.Header.Get(headerContentEncoding) == "gzip" {
			r, errReader := gzip.NewReader(bytes.NewReader(body))
			if errReader == nil {
				var releaseDecoded func()
				body, releaseDecoded, err = file.ReadBody(r)
				defer releaseDecoded()
				_ = r.Close()
				if err == nil {
					detected = http.DetectContentType(body)
				}
			}
		} else {
			detected = http.DetectContentType(body)
		}
	}

	record := &types.HTTP{
		ResContentLength:       contentLength,
		ResContentType:         res.Header.Get(headerContentType),
		StatusCode:             int32(res.StatusCode),
		ServerName:             res.Header.Get("Server"),
		ResContentEncoding:     res.Header.Get(headerContentEncoding),
		ResContentTypeDetected: detected,
		ResCookies:             readCookies(res.Cookies()),
		ResponseHeader:         readHeader(res.Header),
		// Security headers from response
		StrictTransportSecurity:  res.Header.Get("Strict-Transport-Security"),
		ContentSecurityPolicy:    res.Header.Get("Content-Security-Policy"),
		XContentTypeOptions:      res.Header.Get("X-Content-Type-Options"),
		XFrameOptions:            res.Header.Get("X-Frame-Options"),
		XXSSProtection:           res.Header.Get("X-XSS-Protection"),
		ReferrerPolicy:           res.Header.Get("Referrer-Policy"),
		AccessControlAllowOrigin: res.Header.Get("Access-Control-Allow-Origin"),
		HasServerTiming:          res.Header.Get("Server-Timing") != "",
		Server:                   res.Header.Get("Server"),
		XPoweredBy:               res.Header.Get("X-Powered-By"),
	}
	if decoderconfig.Instance != nil && decoderconfig.Instance.IncludePayloads {
		record.ResponseBody = body
	}
	return record
}

// extractAuthType extracts the authorization type from the Authorization header
func extractAuthType(authHeader string) string {
	if authHeader == "" {
		return ""
	}
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) >= 1 {
		return parts[0]
	}
	return ""
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
