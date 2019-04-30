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

package main

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"go.uber.org/zap"
)

// NetcapTransport contains a http.Transport for RoundTrips
// and the target URL of the associated reverse proxy
type NetcapTransport struct {
	proxyName string
	rt        http.RoundTripper
	targetURL *url.URL
}

// RoundTrip implements the http.Transport interface
func (t *NetcapTransport) RoundTrip(req *http.Request) (resp *http.Response, err error) {

	// set basic auth on request if present
	if t.targetURL.User != nil {
		pass, ok := t.targetURL.User.Password()
		if ok {
			req.SetBasicAuth(t.targetURL.User.Username(), pass)
		}
	}

	// rewrite the host header
	req.Host = t.targetURL.Host
	req.Header.Set("Host", t.targetURL.Host)

	if Debug {
		DumpHTTPRequest(req, t.proxyName)
	}

	// start timer
	var start = time.Now()

makeHTTPRequest:
	// start round trip
	resp, err = t.rt.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	// calculate time delta of the initial request
	delta := time.Since(start)

	// handle redirect and special status codes
	switch resp.StatusCode {
	case http.StatusFound: // redirect. modify request and try again
		newLoc := resp.Header.Get("Location")
		req.URL.Path = newLoc

		Log.Info(t.proxyName+" proxy got a redirect.",
			zap.String("newLocation", newLoc),
		)
		goto makeHTTPRequest
	}

	// collect the cookies
	var cookies []string
	for _, c := range req.Cookies() {
		cookies = append(cookies, c.String())
	}

	// read the raw bytes of the response body
	rawbody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if len(rawbody) != 0 {
		// restore resp body or dumping it will fail later
		var b bytes.Buffer
		b.Write(rawbody)
		resp.Body = ioutil.NopCloser(&b)

		// set content length manually in case the service did not
		resp.ContentLength = int64(len(rawbody))
	}

	if Debug {
		DumpHTTPResponse(resp, t.proxyName, rawbody)
	}

	// check X-Forwarded-For header
	// since the host might not always be set
	// for example in case of proxies
	if req.URL.Host == "" {
		req.URL.Host = req.Header.Get("X-Forwarded-For")
		Log.Info("set req.URL.Host to", zap.String("host", req.URL.Host))
	}

	// resp.Header.Get("Content-Encoding")
	// serverName := resp.Header.Get("Server")

	// r := types.HTTP{
	// 	Timestamp: utils.TimeToString(time.Now()),
	// 	// Proto            : string  (),
	// 	Method:           string(req.Method),
	// 	Host:             string(req.Host),
	// 	UserAgent:        string(req.UserAgent()),
	// 	Referer:          string(req.Referer()),
	// 	ReqCookies:       cookies,
	// 	ReqContentLength: int32(req.ContentLength),
	// 	URL:              string(req.URL.String()),
	// 	ResContentLength: int32(resp.ContentLength),
	// 	ContentType:      string(req.Header.Get("Content-Type")),
	// 	StatusCode:       int32(resp.StatusCode),
	// 	SrcIP:            string(req.RemoteAddr),
	// 	// DstIP:            string(),
	// }

	Log.Info("round trip finished",
		zap.Duration("delta", delta),
		zap.String("proxy", t.proxyName),
		zap.String("method", req.Method),
		zap.String("time", delta.String()),
		zap.String("URL", req.URL.String()),
		zap.String("status", resp.Status),
		zap.Int("code", resp.StatusCode),
		zap.Int64("respContentLength", resp.ContentLength),
		zap.Int64("reqContentLength", req.ContentLength),
		zap.String("remoteAddr", req.RemoteAddr),
		zap.String("userAgent", req.UserAgent()),
		zap.String("formValues", req.Form.Encode()),
		zap.Strings("cookies", cookies),
	)

	return resp, nil
}
