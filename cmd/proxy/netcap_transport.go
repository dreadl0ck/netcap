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

package proxy

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"time"

	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/types"
)

// netcapTransport contains a http.Transport for RoundTrips
// and the target URL of the associated reverse proxy.
type netcapTransport struct {
	proxyName string
	rt        http.RoundTripper
	targetURL *url.URL
	proxy     *reverseProxy
}

// RoundTrip implements the http.Transport interface.
func (t *netcapTransport) RoundTrip(req *http.Request) (resp *http.Response, err error) {
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

	if *flagDebug {
		dumpHTTPRequest(req, t.proxyName)
	}

	// Request Tracing
	// collects timing information for TLS, DNS and connection stats
	var (
		startTime         = time.Now()
		tlsHandShakeStart time.Time
		dnsStart          time.Time

		// when tracing is enabled, these additional parameters will be made available on the HTTP audit records
		firstResponseByteDuration time.Duration
		dnsResolvedDuration       time.Duration
		tlsHandshakeDuration      time.Duration
		destIP                    string
	)

	if *flagTrace {
		// create http client trace
		trace := &httptrace.ClientTrace{
			GotConn: func(connInfo httptrace.GotConnInfo) {
				destIP = connInfo.Conn.RemoteAddr().String()
			},
			TLSHandshakeStart: func() {
				tlsHandShakeStart = time.Now()
			},
			TLSHandshakeDone: func(t tls.ConnectionState, e error) {
				// TODO: add tls information to HTTP audit record + ja3
				// fmt.Println("TLSHandshakeDone", t, e)
				tlsHandshakeDuration = time.Since(tlsHandShakeStart)
			},
			DNSDone: func(d httptrace.DNSDoneInfo) {
				// fmt.Println("DNSDone", d)
				dnsResolvedDuration = time.Since(dnsStart)
			},
			DNSStart: func(info httptrace.DNSStartInfo) {
				dnsStart = time.Now()
			},
			GotFirstResponseByte: func() {
				firstResponseByteDuration = time.Since(startTime)
			},
		}

		// add tracing context
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
	}

makeHTTPRequest:
	// start round trip
	resp, err = t.rt.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	// calculate time delta of the initial request
	delta := time.Since(startTime)

	// handle redirect and special status codes
	switch resp.StatusCode {
	// handle redirects
	case http.StatusFound:

		// get new location
		newLoc := resp.Header.Get("Location")

		// modify request
		req.URL.Path = newLoc

		proxyLog.Info(t.proxyName+" proxy got a redirect.",
			zap.String("newLocation", newLoc),
		)

		// try again
		goto makeHTTPRequest
	}

	// collect the cookies for both request and response
	var (
		// TODO: include these into created HTTP audit record
		reqCookies []string
		resCookies []string
	)
	for _, cookie := range req.Cookies() {
		reqCookies = append(reqCookies, cookie.String())
	}

	for _, cookie := range resp.Cookies() {
		resCookies = append(resCookies, cookie.String())
	}

	// read the raw bytes of the response body
	// to set content length manually in case the value in the header is wrong
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

	if *flagDebug {
		dumpHTTPResponse(resp, t.proxyName, rawbody)
	}

	sourceIP := req.RemoteAddr
	if sourceIP == "" {
		sourceIP = getIPAdress(req)
	}

	// create HTTP audit record and populate it with data
	// from both http.Request and http.Response
	r := &types.HTTP{
		Timestamp: startTime.UnixNano(),

		// Request information
		// ReqCookies:         reqCookies,
		Proto:              req.Proto,
		Method:             req.Method,
		Host:               req.URL.Host,
		UserAgent:          req.UserAgent(),
		Referer:            req.Referer(),
		ReqContentLength:   int32(req.ContentLength),
		ContentType:        req.Header.Get("Content-Type"),
		URL:                req.URL.String(),
		ReqContentEncoding: req.Header.Get("Content-Encoding"),

		// Response information
		ResContentLength:   int32(resp.ContentLength),
		StatusCode:         int32(resp.StatusCode),
		ResContentEncoding: resp.Header.Get("Content-Encoding"),
		ServerName:         resp.Header.Get("Server"),

		ResContentType: resp.Header.Get("Content-Type"),
		DoneAfter:      delta.Nanoseconds(),

		// Address information
		SrcIP: sourceIP,

		// available when tracing is enabled
		DstIP:          destIP,
		DNSDoneAfter:   dnsResolvedDuration.Nanoseconds(),
		TLSDoneAfter:   tlsHandshakeDuration.Nanoseconds(),
		FirstByteAfter: firstResponseByteDuration.Nanoseconds(),
	}

	// write record to disk
	err = t.proxy.writer.Write(r)
	if err != nil {
		log.Fatal("failed to write audit record:", err)
	}

	// dump as JSON if configured
	if *flagDump {
		j, errJSON := r.JSON()
		if errJSON != nil {
			log.Fatal(errJSON)
		}

		// pretty print if configured
		if *flagDumpFormatted {
			var b bytes.Buffer

			err = json.Indent(&b, []byte(j), "", " ")
			if err != nil {
				log.Fatal(err)
			}

			fmt.Println(b.String())
		} else {
			fmt.Println(j)
		}
	}

	return resp, nil
}
