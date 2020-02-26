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

// This code is based on the gopacket/examples/reassemblydump/main.go example.
// The following license is provided:
// Copyright (c) 2012 Google, Inc. All rights reserved.
// Copyright (c) 2009-2011 Andreas Krennmair. All rights reserved.

// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:

//    * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//    * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//    * Neither the name of Andreas Krennmair, Google, nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.

// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package encoder

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path"
	"sync"
	"sync/atomic"

	gzip "github.com/klauspost/pgzip"

	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
)

/*
 * HTTP part
 */

type httpReader struct {
	ident    string
	isClient bool
	bytes    chan []byte
	data     []byte
	hexdump  bool
	parent   *tcpStream
}

func (h *httpReader) Read(p []byte) (int, error) {
	ok := true
	for ok && len(h.data) == 0 {
		h.data, ok = <-h.bytes
	}
	if !ok || len(h.data) == 0 {
		return 0, io.EOF
	}

	l := copy(p, h.data)
	h.data = h.data[l:]
	return l, nil
}

func (h *httpReader) cleanup(wg *sync.WaitGroup, s2c Stream, c2s Stream) {

	h.parent.Lock()
	if !h.parent.last {

		// signal wait group
		wg.Done()

		h.parent.last = true
		h.parent.Unlock()

		return
	}
	h.parent.Unlock()

	// cleanup() is called twice - once for each direction of the stream
	// execute the audit record collection only once for the client stream
	// it will collect all requests and responses that have been collected
	if h.parent.last {

		for _, res := range h.parent.responses {

			// populate types.HTTP with all infos from response
			ht := newHTTPFromResponse(res)

			_ = h.findRequest(res, s2c)

			atomic.AddInt64(&httpEncoder.numResponses, 1)

			// now add request information
			if res.Request != nil {
				atomic.AddInt64(&httpEncoder.numRequests, 1)
				setRequest(ht, res.Request)
			} else {
				// response without matching request
				// dont add to output for now
				atomic.AddInt64(&httpEncoder.numUnmatchedResp, 1)
				continue
			}

			// export metrics if configured
			if httpEncoder.export {
				ht.Inc()
			}

			// write record to disk
			atomic.AddInt64(&httpEncoder.numRecords, 1)
			err := httpEncoder.writer.Write(ht)
			if err != nil {
				errorMap.Inc(err.Error())
			}
		}

		for _, req := range h.parent.requests {
			if req != nil {
				h := &types.HTTP{}
				setRequest(h, req)

				atomic.AddInt64(&httpEncoder.numRequests, 1)
				atomic.AddInt64(&httpEncoder.numUnansweredRequests, 1)

				// export metrics if configured
				if httpEncoder.export {
					h.Inc()
				}

				// write record to disk
				atomic.AddInt64(&httpEncoder.numRecords, 1)
				err := httpEncoder.writer.Write(h)
				if err != nil {
					errorMap.Inc(err.Error())
				}
			} else {
				atomic.AddInt64(&httpEncoder.numNilRequests, 1)
			}
		}
	}

	// signal wait group
	wg.Done()
}

// run starts decoding HTTP traffic in a single direction
func (h *httpReader) run(wg *sync.WaitGroup) {

	// create streams
	var (
		// client to server
		c2s = Stream{h.parent.net, h.parent.transport}
		// server to client
		s2c = Stream{h.parent.net.Reverse(), h.parent.transport.Reverse()}
	)

	// defer a cleanup func to flush the requests and responses once the stream encounters an EOF
	defer h.cleanup(wg, s2c, c2s)

	var (
		err error
		b   = bufio.NewReader(h)
	)
	for {
		// handle parsing HTTP requests
		if h.isClient {
			err = h.readRequest(b, c2s)
		} else {
			// handle parsing HTTP responses
			err = h.readResponse(b, s2c)
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			// stop in case of EOF
			break
		} else {
			// continue on all other errors
			continue
		}
	}
}

// HTTP Response

func (h *httpReader) readResponse(b *bufio.Reader, s2c Stream) error {

	// try to read HTTP response from the buffered reader
	res, err := http.ReadResponse(b, nil)
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return err
	} else if err != nil {
		logError("HTTP-response", "HTTP/%s Response error: %s (%v,%+v)\n", h.ident, err, err, err)
		return err
	}

	body, err := ioutil.ReadAll(res.Body)
	s := len(body)
	if err != nil {
		logError("HTTP-response-body", "HTTP/%s: failed to get body(parsed len:%d): %s\n", h.ident, s, err)
		// continue execution
	}
	if h.hexdump {
		logInfo("Body(%d/0x%x)\n%s\n", len(body), len(body), hex.Dump(body))
	}
	res.Body.Close()

	sym := ","
	if res.ContentLength > 0 && res.ContentLength != int64(s) {
		sym = "!="
	}

	// determine content type
	contentType, ok := res.Header["Content-Type"]
	if !ok {
		contentType = []string{http.DetectContentType(body)}
	}

	encoding := res.Header["Content-Encoding"]
	logInfo("HTTP/%s Response: %s (%d%s%d%s) -> %s\n", h.ident, res.Status, res.ContentLength, sym, s, contentType, encoding)

	// increment counter
	mu.Lock()
	responses++
	mu.Unlock()

	h.parent.Lock()
	h.parent.responses = append(h.parent.responses, res)
	h.parent.Unlock()

	// write responses to disk if configured
	if (err == nil || *writeincomplete) && *output != "" {
		return h.saveResponse(err, body, encoding, h.ident)
	}

	return nil
}

func (h *httpReader) findRequest(res *http.Response, s2c Stream) string {

	// try to find the matching HTTP request for the response
	var (
		req    *http.Request
		reqURL string
	)

	h.parent.Lock()
	if len(h.parent.requests) != 0 {
		// take the request from the parent stream and delete it from there
		req, h.parent.requests = h.parent.requests[0], h.parent.requests[1:]
		reqURL = req.URL.String()
	}
	h.parent.Unlock()

	// set request instance on response
	if req != nil {
		res.Request = req
		atomic.AddInt64(&httpEncoder.numFoundRequests, 1)
	}

	return reqURL
}

func (h *httpReader) saveResponse(err error, body []byte, encoding []string, reqURL string) error {
	var (
		ctype = http.DetectContentType(body)
		root  = path.Join(*output, ctype)
		base  = url.QueryEscape(path.Base(reqURL))
	)
	if err != nil {
		base = "incomplete-" + base
	}

	// make sure root path exists
	os.MkdirAll(root, 0755)
	base = path.Join(root, base)
	if len(base) > 250 {
		base = base[:250] + "..."
	}
	if base == *output {
		base = path.Join(*output, "noname")
	}
	var (
		target = base
		n      = 0
	)
	for {
		_, err := os.Stat(target)
		if err != nil {
			break
		}
		target = fmt.Sprintf("%s-%d", base, n)
		n++
	}

	f, err := os.Create(target)
	if err != nil {
		logError("HTTP-create", "Cannot create %s: %s\n", target, err)
		return err
	}

	// explicitely declare io.Reader interface
	var r io.Reader

	// now assign a new buffer
	r = bytes.NewBuffer(body)
	if len(encoding) > 0 && (encoding[0] == "gzip" || encoding[0] == "deflate") {
		r, err = gzip.NewReader(r)
		if err != nil {
			logError("HTTP-gunzip", "Failed to gzip decode: %s", err)
		}
	}
	if err == nil {
		w, err := io.Copy(f, r)
		if _, ok := r.(*gzip.Reader); ok {
			r.(*gzip.Reader).Close()
		}
		f.Close()
		if err != nil {
			logError("HTTP-save", "%s: failed to save %s (l:%d): %s\n", h.ident, target, w, err)
		} else {
			logInfo("%s: Saved %s (l:%d)\n", h.ident, target, w)
		}
	}

	return nil
}

// HTTP Request

func (h *httpReader) readRequest(b *bufio.Reader, c2s Stream) error {
	req, err := http.ReadRequest(b)
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return err
	} else if err != nil {
		logError("HTTP-request", "HTTP/%s Request error: %s (%v,%+v)\n", h.ident, err, err, err)
		return err
	}

	body, err := ioutil.ReadAll(req.Body)
	s := len(body)
	if err != nil {
		logError("HTTP-request-body", "Got body err: %s\n", err)
		// continue execution
	} else if h.hexdump {
		logInfo("Body(%d/0x%x)\n%s\n", len(body), len(body), hex.Dump(body))
	}
	req.Body.Close()

	logInfo("HTTP/%s Request: %s %s (body:%d)\n", h.ident, req.Method, req.URL, s)

	// set some infos for netcap on the HTTP request header
	req.Header.Set("netcap-ts", utils.TimeToString(h.parent.firstPacket))
	req.Header.Set("netcap-clientip", h.parent.net.Src().String())
	req.Header.Set("netcap-serverip", h.parent.net.Dst().String())

	// increase counter
	mu.Lock()
	requests++
	mu.Unlock()

	h.parent.Lock()
	h.parent.requests = append(h.parent.requests, req)
	h.parent.Unlock()

	return nil
}
