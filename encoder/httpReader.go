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
	"github.com/dreadl0ck/cryptoutils"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

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
		select {
			case h.data, ok = <-h.bytes:
			case <-time.After(timeout):
				return 0, io.EOF
		}
	}
	if !ok || len(h.data) == 0 {
		return 0, io.EOF
	}

	l := copy(p, h.data)
	h.data = h.data[l:]
	return l, nil
}

func (h *httpReader) BytesChan() chan []byte {
	return h.bytes
}

func (h *httpReader) Cleanup(wg *sync.WaitGroup, s2c Stream, c2s Stream) {

	// determine if one side of the stream has already been closed
	h.parent.Lock()
	if !h.parent.last {

		// signal wait group
		wg.Done()

		// indicate close on the parent tcpStream
		h.parent.last = true

		// free lock
		h.parent.Unlock()

		return
	}
	h.parent.Unlock()

	// cleanup() is called twice - once for each direction of the stream
	// this check ensures the audit record collection is executed only if one side has been closed already
	// to ensure all necessary requests and responses are present
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
func (h *httpReader) Run(wg *sync.WaitGroup) {

	// create streams
	var (
		// client to server
		c2s = Stream{h.parent.net, h.parent.transport}
		// server to client
		s2c = Stream{h.parent.net.Reverse(), h.parent.transport.Reverse()}
	)

	// defer a cleanup func to flush the requests and responses once the stream encounters an EOF
	defer h.Cleanup(wg, s2c, c2s)

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
	} else {
		res.Body.Close()

		// Restore body so it can be read again
		res.Body = ioutil.NopCloser(bytes.NewBuffer(body))
	}
	if h.hexdump {
		logInfo("Body(%d/0x%x)\n%s\n", len(body), len(body), hex.Dump(body))
	}

	sym := ","
	if res.ContentLength > 0 && res.ContentLength != int64(s) {
		sym = "!="
	}

	// determine content type for debug log
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
	if (err == nil || *writeincomplete) && FileStorage != "" {

		h.parent.Lock()
		var (
			name = "unknown"
			numResponses = len(h.parent.responses)
			numRequests = len(h.parent.requests)
		)
		h.parent.Unlock()

		// check if there is a matching request for the current stream
		if numRequests >= numResponses {

			// fetch it
			h.parent.Lock()
			req := h.parent.requests[numResponses-1]
			h.parent.Unlock()
			if req != nil {
				name = path.Base(req.URL.Path)
			}
		}

		// save file to disk
		return h.saveFile("HTTP RESPONSE", name, err, body, encoding)
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

func fileExtensionForContentType(typ string) string {

	// types from: https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types/Common_types
	switch typ {
	case "application/x-gzip":
		return ".gz"
	case "image/jpg":
		return ".jpg"
	case "text/plain; charset=utf-8":
		return ".txt"
	case "text/plain; charset=UTF-8":
		return ".txt"
	case "text/html; charset=utf-8":
		return ".html"
	case "text/html; charset=UTF-8":
		return ".html"
	case "image/x-icon":
		return ".ico"
	case "audio/aac":
		return ".aac"
	case "application/x-abiword":
		return ".abw"
	case "application/x-freearc":
		return ".arc"
	case "video/x-msvideo":
		return ".avi"
	case "application/vnd.amazon.ebook":
		return ".azw"
	case "application/octet-stream":
		return ".bin"
	case "image/bmp":
		return ".bmp"
	case "application/x-bzip":
		return ".bz"
	case "application/x-bzip2":
		return ".bz2"
	case "application/x-csh":
		return ".csh"
	case "text/css":
		return ".css"
	case "text/csv":
		return ".csv"
	case "application/msword":
		return ".doc"
	case "application/vnd.openxmlformats-officedocument.wordprocessingml.document":
		return ".docx"
	case "application/vnd.ms-fontobject":
		return ".eot"
	case "application/epub+zip":
		return ".epub"
	case "application/gzip":
		return ".gz"
	case "image/gif":
		return ".gif"
	case "text/html":
		return ".html"
	case "image/vnd.microsoft.icon":
		return ".ico"
	case "text/calendar":
		return ".ics"
	case "application/java-archive":
		return ".jar"
	case "image/jpeg":
		return ".jpg"
	case "text/javascript":
		return ".js"
	case "application/json":
		return ".json"
	case "application/ld+json":
		return ".jsonld"
	case "audio/midi audio/x-midi":
		return ".midi"
	case "audio/mpeg":
		return ".mp3"
	case "video/mpeg":
		return ".mpeg"
	case "application/vnd.apple.installer+xml":
		return ".mpkg"
	case "application/vnd.oasis.opendocument.presentation":
		return ".odp"
	case "application/vnd.oasis.opendocument.spreadsheet":
		return ".ods"
	case "application/vnd.oasis.opendocument.text":
		return ".odt"
	case "audio/ogg":
		return ".oga"
	case "video/ogg":
		return ".ogv"
	case "application/ogg":
		return ".ogx"
	case "audio/opus":
		return ".opus"
	case "font/otf":
		return ".otf"
	case "image/png":
		return ".png"
	case "application/pdf":
		return ".pdf"
	case "application/php":
		return ".php"
	case "application/vnd.ms-powerpoint":
		return ".ppt"
	case "application/vnd.openxmlformats-officedocument.presentationml.presentation":
		return ".pptx"
	case "application/vnd.rar":
		return ".rar"
	case "application/rtf":
		return ".rtf"
	case "application/x-sh":
		return ".sh"
	case "image/svg+xml":
		return ".svg"
	case "application/x-shockwave-flash":
		return ".swf"
	case "application/x-tar":
		return ".tar"
	case "image/tiff":
		return ".tiff"
	case "video/mp2t":
		return ".ts"
	case "font/ttf":
		return ".ttf"
	case "text/plain":
		return ".txt"
	case "application/vnd.visio":
		return ".vsd"
	case "audio/wav":
		return ".wav"
	case "audio/webm":
		return ".weba"
	case "video/webm":
		return ".webm"
	case "image/webp":
		return ".webp"
	case "font/woff":
		return ".woff"
	case "font/woff2":
		return ".woff2"
	case "application/xhtml+xml":
		return ".xhtml"
	case "application/vnd.ms-excel":
		return ".xls"
	case "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":
		return ".xlsx"
	case "application/xml":
		return ".xml"
	case "application/vnd.mozilla.xul+xml":
		return ".xul"
	case "application/zip":
		return ".zip"
	case "video/3gpp":
		return ".3gp"
	case "video/3gpp2":
		return ".3g2"
	case "application/x-7z-compressed":
		return ".7z"
	}

	return ""
}

func (h *httpReader) saveFile(source, name string, err error, body []byte, encoding []string) error {

	// prevent saving zero bytes
	if len(body) == 0 {
		return nil
	}

	if name == "" || name == "/" {
		name = "unknown"
	}

	var (
		fileName string

		// detected content type
		ctype = http.DetectContentType(body)

		// root path
		root  = path.Join(FileStorage, ctype)

		// file extension
		ext = fileExtensionForContentType(ctype)

		// file basename
		base  = filepath.Clean(name + "-" + path.Base(h.ident)) + ext
	)
	if err != nil {
		base = "incomplete-" + base
	}
	if filepath.Ext(name) == "" {
		fileName = name + ext
	} else {
		fileName = name
	}

	// make sure root path exists
	os.MkdirAll(root, 0755)
	base = path.Join(root, base)
	if len(base) > 250 {
		base = base[:250] + "..."
	}
	if base == FileStorage {
		base = path.Join(FileStorage, "noname")
	}
	var (
		target = base
		n      = 0
	)
	for {
		_, errStat := os.Stat(target)
		if errStat != nil {
			break
		}

		if err != nil {
			target = path.Join(root, filepath.Clean("incomplete-" + name + "-" + h.ident) + "-" + strconv.Itoa(n) + fileExtensionForContentType(ctype))
		} else {
			target = path.Join(root, filepath.Clean(name + "-" + h.ident) + "-" + strconv.Itoa(n) + fileExtensionForContentType(ctype))
		}

		n++
	}

	//fmt.Println("saving file:", target)

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

	// write file to disk
	writeFile(&types.File{
		Timestamp: h.parent.firstPacket.String(),
		Name:      fileName,
		Length:    int64(len(body)),
		Hash:      hex.EncodeToString(cryptoutils.MD5Data(body)),
		Location:  target,
		Ident:     h.ident,
		Source:    source,
		ContentType: ctype,
		Context:  &types.PacketContext{
			SrcIP:   h.parent.net.Src().String(),
			DstIP:   h.parent.net.Dst().String(),
			SrcPort: h.parent.transport.Src().String(),
			DstPort: h.parent.transport.Dst().String(),
		},
	})

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
	} else {
		req.Body.Close()

		// Restore body so it can be read again
		req.Body = ioutil.NopCloser(bytes.NewBuffer(body))
	}
	if h.hexdump {
		logInfo("Body(%d/0x%x)\n%s\n", len(body), len(body), hex.Dump(body))
	}

	logInfo("HTTP/%s Request: %s %s (body:%d)\n", h.ident, req.Method, req.URL, s)

	// TODO: create a wrapper struct that contains these fields and keeps a reference to the http.Request
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

	if req.Method == "POST" {
		// write request payload to disk if configured
		if (err == nil || *writeincomplete) && FileStorage != "" {
			return h.saveFile(
				"HTTP POST REQUEST",
				path.Base(req.URL.Path),
				err,
				body,
				req.Header["Content-Encoding"],
			)
		}
	}

	return nil
}
