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
	"compress/gzip"
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

func Error(t string, s string, a ...interface{}) {
	errorsMapMutex.Lock()
	numErrors++
	nb, _ := errorsMap[t]
	errorsMap[t] = nb + 1
	errorsMapMutex.Unlock()
	if outputLevel >= 0 {
		fmt.Printf(s, a...)
	}
}

func Info(s string, a ...interface{}) {
	if outputLevel >= 1 {
		fmt.Printf(s, a...)
	}
}

func Debug(s string, a ...interface{}) {
	if outputLevel >= 2 {
		fmt.Printf(s, a...)
	}
}

func cleanup(wg *sync.WaitGroup, s2c Stream, c2s Stream) {

	// flush from response map
	resMutex.Lock()
	if resArr, ok := httpResMap[s2c]; ok {

		for _, res := range resArr {

			// populate types.HTTP with all infos from request
			h := &types.HTTP{
				ResContentLength: int32(res.ContentLength),
				ContentType:      res.Header.Get("Content-Type"),
				StatusCode:       int32(res.StatusCode),
			}

			if res.Request != nil {
				setRequest(h, res.Request)
			} else {
				// response without matching request
				// dont add to output for now
				continue
			}

			atomic.AddInt64(&httpEncoder.numRecords, 1)
			if httpEncoder.csv {
				_, err := httpEncoder.csvWriter.WriteRecord(h)
				if err != nil {
					errorMap.Inc(err.Error())
				}
			} else {
				err := httpEncoder.aWriter.PutProto(h)
				if err != nil {
					errorMap.Inc(err.Error())
				}
			}
		}

		// clean up
		delete(httpResMap, s2c)
	}
	resMutex.Unlock()

	// flush from requests map
	reqMutex.Lock()
	if reqArr, ok := httpReqMap[c2s]; ok {
		for _, req := range reqArr {
			if req != nil {
				h := &types.HTTP{}
				setRequest(h, req)

				if httpEncoder.csv {
					_, err := httpEncoder.csvWriter.WriteRecord(h)
					if err != nil {
						errorMap.Inc(err.Error())
					}
				} else {
					err := httpEncoder.aWriter.PutProto(h)
					if err != nil {
						errorMap.Inc(err.Error())
					}
				}
			}
		}

		// clean up
		delete(httpReqMap, c2s)
	}
	reqMutex.Unlock()

	// signal wait group
	wg.Done()
}

func (h *httpReader) run(wg *sync.WaitGroup) {

	// create streams
	var (
		c2s = Stream{h.parent.net, h.parent.transport}
		s2c = Stream{h.parent.net.Reverse(), h.parent.transport.Reverse()}
	)

	// defer a cleanup func to flush the requests and responses once the stream encounters an EOF
	defer cleanup(wg, s2c, c2s)

	b := bufio.NewReader(h)
	for {
		if h.isClient {

			req, err := http.ReadRequest(b)
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			} else if err != nil {
				Error("HTTP-request", "HTTP/%s Request error: %s (%v,%+v)\n", h.ident, err, err, err)
				continue
			}

			body, err := ioutil.ReadAll(req.Body)
			s := len(body)
			if err != nil {
				Error("HTTP-request-body", "Got body err: %s\n", err)
			} else if h.hexdump {
				Info("Body(%d/0x%x)\n%s\n", len(body), len(body), hex.Dump(body))
			}
			req.Body.Close()

			Info("HTTP/%s Request: %s %s (body:%d)\n", h.ident, req.Method, req.URL, s)
			req.Header.Set("netcap-ts", utils.TimeToString(h.parent.firstPacket))
			req.Header.Set("netcap-clientip", h.parent.net.Src().String())
			req.Header.Set("netcap-serverip", h.parent.net.Dst().String())

			mu.Lock()
			requests++
			mu.Unlock()

			h.parent.Lock()
			h.parent.urls = append(h.parent.urls, req.URL.String())
			h.parent.requests = append(h.parent.requests, req)
			h.parent.Unlock()

			// add to map
			reqMutex.Lock()
			httpReqMap[c2s] = append(httpReqMap[c2s], req)
			reqMutex.Unlock()
		} else {
			res, err := http.ReadResponse(b, nil)
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			} else if err != nil {
				Error("HTTP-response", "HTTP/%s Response error: %s (%v,%+v)\n", h.ident, err, err, err)
				continue
			}

			var (
				req    *http.Request
				reqURL string
			)

			h.parent.Lock()
			if len(h.parent.requests) != 0 {
				req, h.parent.requests = h.parent.requests[0], h.parent.requests[1:]
			}
			if len(h.parent.urls) == 0 {
				reqURL = fmt.Sprintf("<no-request-seen>")
			} else {
				reqURL, h.parent.urls = h.parent.urls[0], h.parent.urls[1:]
			}
			h.parent.Unlock()

			// set request instance on response
			if req != nil {
				res.Request = req

				// create client stream
				st := Stream{h.parent.net, h.parent.transport}

				// remove request from map
				reqMutex.Lock()
				if requests, ok := httpReqMap[st]; ok {
					for i, r := range requests {
						if r == req {
							requests = append(requests[:i], requests[i+1:]...)
							httpReqMap[st] = requests
							break
						}
					}
				}
				reqMutex.Unlock()
			}

			body, err := ioutil.ReadAll(res.Body)
			s := len(body)
			if err != nil {
				Error("HTTP-response-body", "HTTP/%s: failed to get body(parsed len:%d): %s\n", h.ident, s, err)
			}
			if h.hexdump {
				Info("Body(%d/0x%x)\n%s\n", len(body), len(body), hex.Dump(body))
			}
			res.Body.Close()
			sym := ","
			if res.ContentLength > 0 && res.ContentLength != int64(s) {
				sym = "!="
			}
			contentType, ok := res.Header["Content-Type"]
			if !ok {
				contentType = []string{http.DetectContentType(body)}
			}
			encoding := res.Header["Content-Encoding"]
			Info("HTTP/%s Response: %s URL:%s (%d%s%d%s) -> %s\n", h.ident, res.Status, reqURL, res.ContentLength, sym, s, contentType, encoding)

			mu.Lock()
			responses++
			mu.Unlock()

			// add to map
			resMutex.Lock()
			httpResMap[s2c] = append(httpResMap[s2c], res)
			resMutex.Unlock()
			if (err == nil || *writeincomplete) && *output != "" {

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
				for true {
					_, err := os.Stat(target)
					//if os.IsNotExist(err) != nil {
					if err != nil {
						break
					}
					target = fmt.Sprintf("%s-%d", base, n)
					n++
				}

				f, err := os.Create(target)
				if err != nil {
					Error("HTTP-create", "Cannot create %s: %s\n", target, err)
					continue
				}
				var r io.Reader
				r = bytes.NewBuffer(body)
				if len(encoding) > 0 && (encoding[0] == "gzip" || encoding[0] == "deflate") {
					r, err = gzip.NewReader(r)
					if err != nil {
						Error("HTTP-gunzip", "Failed to gzip decode: %s", err)
					}
				}
				if err == nil {
					w, err := io.Copy(f, r)
					if _, ok := r.(*gzip.Reader); ok {
						r.(*gzip.Reader).Close()
					}
					f.Close()
					if err != nil {
						Error("HTTP-save", "%s: failed to save %s (l:%d): %s\n", h.ident, target, w, err)
					} else {
						Info("%s: Saved %s (l:%d)\n", h.ident, target, w)
					}
				}
			}
		}
	}
}
