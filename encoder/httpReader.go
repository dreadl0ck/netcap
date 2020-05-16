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
	"github.com/dreadl0ck/cryptoutils"
	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/netcap/reassembly"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
	"github.com/mgutz/ansi"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	deadlock "github.com/sasha-s/go-deadlock"

	"sync/atomic"
	"time"
)

// HTTPMetaStore is a thread safe in-memory store for interesting HTTP artifacts
type HTTPMetaStore struct {

	// mapped ip address to server names
	ServerNames map[string]string

	// mapped ip address to user agents
	UserAgents map[string]string

	// mapped ip address to user agents
	Vias map[string]string

	// mapped ip address to user agents
	XPoweredBy map[string]string

	deadlock.Mutex
}

var httpStore = &HTTPMetaStore{
	ServerNames: make(map[string]string),
	UserAgents:  make(map[string]string),
	Vias:        make(map[string]string),
	XPoweredBy:  make(map[string]string),
}

/*
 * HTTP
 */

type httpRequest struct {
	request   *http.Request
	timestamp string
	clientIP  string
	serverIP  string
}

type httpResponse struct {
	response  *http.Response
	timestamp string
	clientIP  string
	serverIP  string
}

type httpReader struct {
	ident              string
	isClient           bool
	dataChan              chan *Data
	data               []*Data
	merged             DataSlice
	hexdump            bool
	parent             *tcpConnection
	saved              bool
	serviceBanner      bytes.Buffer
	serviceBannerBytes int
	numBytes           int
}

func (h *httpReader) Read(p []byte) (int, error) {

	var (
		ok = true
		data *Data
	)

	data, ok = <-h.dataChan
	if data == nil || !ok {
		return 0, io.EOF
	}

	// copy received data into the passed in buffer
	l := copy(p, data.raw)

	h.parent.Lock()
	h.data = append(h.data, data)
	h.numBytes += l
	h.parent.Unlock()

	return l, nil
}

func (h *httpReader) DataChan() chan *Data {
	return h.dataChan
}

func (h *httpReader) Cleanup(f *tcpConnectionFactory, s2c Connection, c2s Connection) {

	// determine if one side of the stream has already been closed
	h.parent.Lock()
	if !h.parent.last {

		// signal wait group
		f.wg.Done()
		f.Lock()
		f.numActive--
		f.Unlock()

		// indicate close on the parent tcpConnection
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
			ht := newHTTPFromResponse(res.response)

			_ = h.findRequest(res.response, s2c)

			atomic.AddInt64(&httpEncoder.numResponses, 1)

			// now add request information
			if res.response.Request != nil {
				atomic.AddInt64(&httpEncoder.numRequests, 1)
				setRequest(ht, &httpRequest{
					request:   res.response.Request,
					timestamp: res.timestamp,
					clientIP:  res.clientIP,
					serverIP:  res.serverIP,
				})

				if u, p, ok := res.response.Request.BasicAuth(); ok {
					if u != "" || p != "" {
						writeCredentials(&types.Credentials{
							Timestamp: h.parent.firstPacket.String(),
							Service:   "HTTP Basic Auth",
							Flow:      h.parent.ident,
							User:      u,
							Password:  p,
						})
					}
				}
			} else {
				// response without matching request
				// dont add to output for now
				atomic.AddInt64(&httpEncoder.numUnmatchedResp, 1)
				continue
			}

			writeHTTP(ht)
		}

		for _, req := range h.parent.requests {
			if req != nil {
				ht := &types.HTTP{}
				setRequest(ht, req)

				atomic.AddInt64(&httpEncoder.numRequests, 1)
				atomic.AddInt64(&httpEncoder.numUnansweredRequests, 1)

				if u, p, ok := req.request.BasicAuth(); ok {
					if u != "" || p != "" {
						writeCredentials(&types.Credentials{
							Timestamp: h.parent.firstPacket.String(),
							Service:   "HTTP Basic Auth",
							Flow:      h.parent.ident,
							User:      u,
							Password:  p,
						})
					}
				}

				writeHTTP(ht)
			} else {
				atomic.AddInt64(&httpEncoder.numNilRequests, 1)
			}
		}
	}

	// signal wait group
	f.wg.Done()
	f.Lock()
	f.numActive--
	f.Unlock()
}

func writeHTTP(h *types.HTTP) {

	httpStore.Lock()

	if h.UserAgent != "" {
		if ua, ok := httpStore.UserAgents[h.SrcIP]; ok {
			if !strings.Contains(ua, h.UserAgent) {
				httpStore.UserAgents[h.SrcIP] = ua + "| " + h.UserAgent
			}
		} else {
			httpStore.UserAgents[h.SrcIP] = h.UserAgent
		}
	}

	if h.ServerName != "" {
		if sn, ok := httpStore.ServerNames[h.DstIP]; ok {
			if !strings.Contains(sn, h.ServerName) {
				httpStore.ServerNames[h.DstIP] = sn + "| " + h.ServerName
			}
		} else {
			httpStore.ServerNames[h.DstIP] = h.ServerName
		}
	}

	if val, ok := h.ResponseHeader["Via"]; ok {
		if sn, ok := httpStore.Vias[h.DstIP]; ok {
			if !strings.Contains(sn, val) {
				httpStore.Vias[h.DstIP] = sn + "| " + val
			}
		} else {
			httpStore.Vias[h.DstIP] = val
		}
	}

	if val, ok := h.ResponseHeader["X-Powered-By"]; ok {
		if sn, ok := httpStore.XPoweredBy[h.DstIP]; ok {
			if !strings.Contains(sn, val) {
				httpStore.XPoweredBy[h.DstIP] = sn + "| " + val
			}
		} else {
			httpStore.XPoweredBy[h.DstIP] = val
		}
	}

	httpStore.Unlock()

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
}

// run starts decoding HTTP traffic in a single direction
func (h *httpReader) Run(f *tcpConnectionFactory) {

	// create streams
	var (
		// client to server
		c2s = Connection{h.parent.net, h.parent.transport}
		// server to client
		s2c = Connection{h.parent.net.Reverse(), h.parent.transport.Reverse()}
	)

	// defer a cleanup func to flush the requests and responses once the stream encounters an EOF
	defer h.Cleanup(f, s2c, c2s)

	var (
		err error
		b   = bufio.NewReader(h)
	)

	h.parent.Lock()
	isClient := h.isClient
	h.parent.Unlock()

	for {
		// handle parsing HTTP requests
		if isClient {
			err = h.readRequest(b, c2s)
		} else {
			// handle parsing HTTP responses
			err = h.readResponse(b, s2c)
		}
		if err != nil {

			// exit on EOF
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				return
			}

			utils.ReassemblyLog.Println("HTTP stream encountered an error", c2s, err)

			// continue processing the stream
			continue
		}
	}
}

// HTTP Response

func (h *httpReader) readResponse(b *bufio.Reader, s2c Connection) error {

	// try to read HTTP response from the buffered reader
	res, err := http.ReadResponse(b, nil)
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return err
	} else if err != nil {
		logReassemblyError("HTTP-response", "HTTP/%s Response error: %s (%v,%+v)\n", h.ident, err, err, err)
		return err
	}

	body, err := ioutil.ReadAll(res.Body)
	s := len(body)
	if err != nil {
		logReassemblyError("HTTP-response-body", "HTTP/%s: failed to get body(parsed len:%d): %s\n", h.ident, s, err)
	} else {
		res.Body.Close()

		// Restore body so it can be read again
		res.Body = ioutil.NopCloser(bytes.NewBuffer(body))
	}
	if h.hexdump {
		logReassemblyInfo("Body(%d/0x%x)\n%s\n", len(body), len(body), hex.Dump(body))
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
	logReassemblyInfo("HTTP/%s Response: %s (%d%s%d%s) -> %s\n", h.ident, res.Status, res.ContentLength, sym, s, contentType, encoding)

	// increment counter
	statsMutex.Lock()
	responses++
	statsMutex.Unlock()

	h.parent.Lock()
	h.parent.responses = append(h.parent.responses, &httpResponse{
		response:  res,
		timestamp: h.parent.firstPacket.String(),
		clientIP:  h.parent.net.Src().String(),
		serverIP:  h.parent.net.Dst().String(),
	})
	h.parent.Unlock()

	// write responses to disk if configured
	if (err == nil || c.WriteIncomplete) && c.FileStorage != "" {

		h.parent.Lock()
		var (
			name         = "unknown"
			host         string
			source       = "HTTP RESPONSE"
			ctype        string
			numResponses = len(h.parent.responses)
			numRequests  = len(h.parent.requests)
		)
		h.parent.Unlock()

		// check if there is a matching request for the current stream
		if numRequests >= numResponses {

			// fetch it
			h.parent.Lock()
			req := h.parent.requests[numResponses-1]
			h.parent.Unlock()
			if req != nil {
				name = path.Base(req.request.URL.Path)
				source += " from " + req.request.URL.Path
				host = req.request.Host
				ctype = strings.Join(req.request.Header["Content-Type"], " ")
			}
		}

		// save file to disk
		return h.saveFile(host, source, name, err, body, encoding, ctype)
	}

	return nil
}

func (h *httpReader) findRequest(res *http.Response, s2c Connection) string {

	// try to find the matching HTTP request for the response
	var (
		req    *http.Request
		reqURL string
	)

	h.parent.Lock()
	if len(h.parent.requests) != 0 {
		// take the request from the parent stream and delete it from there
		req, h.parent.requests = h.parent.requests[0].request, h.parent.requests[1:]
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

	parts := strings.Split(typ, ";")
	if len(typ) > 1 {
		typ = parts[0]
	}

	// types from: https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types/Common_types
	switch typ {
	case "application/x-gzip":
		return ".gz"
	case "image/jpg":
		return ".jpg"
	case "text/plain":
		return ".txt"
	case "text/html":
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
	case "text/xml":
		return ".xml"
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

func trimEncoding(ctype string) string {
	parts := strings.Split(ctype, ";")
	if len(parts) > 1 {
		return parts[0]
	}
	return ctype
}

func (h *httpReader) saveFile(host, source, name string, err error, body []byte, encoding []string, contentType string) error {

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
		ctype = trimEncoding(http.DetectContentType(body))

		// root path
		root = path.Join(c.FileStorage, ctype)

		// file extension
		ext = fileExtensionForContentType(ctype)

		// file basename
		base = filepath.Clean(name+"-"+path.Base(h.ident)) + ext
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
	os.MkdirAll(root, directoryPermission)
	base = path.Join(root, base)
	if len(base) > 250 {
		base = base[:250] + "..."
	}
	if base == c.FileStorage {
		base = path.Join(c.FileStorage, "noname")
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
			target = path.Join(root, filepath.Clean("incomplete-"+name+"-"+h.ident)+"-"+strconv.Itoa(n)+fileExtensionForContentType(ctype))
		} else {
			target = path.Join(root, filepath.Clean(name+"-"+h.ident)+"-"+strconv.Itoa(n)+fileExtensionForContentType(ctype))
		}

		n++
	}

	utils.DebugLog.Println("saving file:", target)

	f, err := os.Create(target)
	if err != nil {
		logReassemblyError("HTTP-create", "Cannot create %s: %s\n", target, err)
		return err
	}

	// explicitely declare io.Reader interface
	var r io.Reader

	// now assign a new buffer
	r = bytes.NewBuffer(body)
	if len(encoding) > 0 && (encoding[0] == "gzip" || encoding[0] == "deflate") {
		r, err = gzip.NewReader(r)
		if err != nil {
			logReassemblyError("HTTP-gunzip", "Failed to gzip decode: %s", err)
		}
	}
	if err == nil {
		w, err := io.Copy(f, r)
		if _, ok := r.(*gzip.Reader); ok {
			r.(*gzip.Reader).Close()
		}
		f.Close()
		if err != nil {
			logReassemblyError("HTTP-save", "%s: failed to save %s (l:%d): %s\n", h.ident, target, w, err)
		} else {
			logReassemblyInfo("%s: Saved %s (l:%d)\n", h.ident, target, w)
		}
	}

	// write file to disk
	writeFile(&types.File{
		Timestamp:           h.parent.firstPacket.String(),
		Name:                fileName,
		Length:              int64(len(body)),
		Hash:                hex.EncodeToString(cryptoutils.MD5Data(body)),
		Location:            target,
		Ident:               h.ident,
		Source:              source,
		ContentTypeDetected: ctype,
		ContentType:         contentType,
		Context: &types.PacketContext{
			SrcIP:   h.parent.net.Src().String(),
			DstIP:   h.parent.net.Dst().String(),
			SrcPort: h.parent.transport.Src().String(),
			DstPort: h.parent.transport.Dst().String(),
		},
	})

	return nil
}

// HTTP Request

func (h *httpReader) readRequest(b *bufio.Reader, c2s Connection) error {
	req, err := http.ReadRequest(b)
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return err
	} else if err != nil {
		logReassemblyError("HTTP-request", "HTTP/%s Request error: %s (%v,%+v)\n", h.ident, err, err, err)
		return err
	}

	body, err := ioutil.ReadAll(req.Body)
	s := len(body)
	if err != nil {
		logReassemblyError("HTTP-request-body", "Got body err: %s\n", err)
		// continue execution
	} else {
		req.Body.Close()

		// Restore body so it can be read again
		req.Body = ioutil.NopCloser(bytes.NewBuffer(body))
	}
	if h.hexdump {
		logReassemblyInfo("Body(%d/0x%x)\n%s\n", len(body), len(body), hex.Dump(body))
	}

	logReassemblyInfo("HTTP/%s Request: %s %s (body:%d)\n", h.ident, req.Method, req.URL, s)

	h.parent.Lock()
	t := utils.TimeToString(h.parent.firstPacket)
	h.parent.Unlock()

	request := &httpRequest{
		request:   req,
		timestamp: t,
		clientIP:  h.parent.net.Src().String(),
		serverIP:  h.parent.net.Dst().String(),
	}

	// parse form values
	req.ParseForm()

	// increase counter
	statsMutex.Lock()
	requests++
	statsMutex.Unlock()

	h.parent.Lock()
	h.parent.requests = append(h.parent.requests, request)
	h.parent.Unlock()

	if req.Method == "POST" {
		// write request payload to disk if configured
		if (err == nil || c.WriteIncomplete) && c.FileStorage != "" {
			return h.saveFile(
				req.Host,
				"HTTP POST REQUEST to "+req.URL.Path,
				path.Base(req.URL.Path),
				err,
				body,
				req.Header["Content-Encoding"],
				strings.Join(req.Header["Content-Type"], " "),
			)
		}
	}

	return nil
}

func (h *httpReader) DataSlice() DataSlice {
	return h.data
}

func (h *httpReader) ClientStream() []byte {
	return nil
}

func (h *httpReader) ServerStream() []byte {
	var buf bytes.Buffer

	h.parent.Lock()
	defer h.parent.Unlock()

	// save server stream for banner identification
	// stores c.BannerSize number of bytes of the server side stream
	for _, d := range h.parent.server.DataSlice() {
		for _, b := range d.raw {
			buf.WriteByte(b)
		}
	}

	return buf.Bytes()
}

func (h *httpReader) ConversationRaw() []byte {
	h.parent.Lock()
	defer h.parent.Unlock()

	// do this only once, this method will be called once for each side of a connection
	if len(h.merged) == 0 {

		// concatenate both client and server data fragments
		h.merged = append(h.parent.client.DataSlice(), h.parent.server.DataSlice()...)

		// sort based on their timestamps
		sort.Sort(h.merged)

		// create the buffer with the entire conversation
		for _, d := range h.merged {

			//fmt.Println(h.ident, d.ac.GetCaptureInfo().Timestamp, d.ac.GetCaptureInfo().Length)

			h.parent.conversationRaw.Write(d.raw)
			if d.dir == reassembly.TCPDirClientToServer {
				if c.Debug {
					h.parent.conversationColored.WriteString(ansi.Red + string(d.raw) + ansi.Reset + "\n[" + d.ac.GetCaptureInfo().Timestamp.String() + "]\n")
				} else {
					h.parent.conversationColored.WriteString(ansi.Red + string(d.raw) + ansi.Reset)
				}
			} else {
				if c.Debug {
					h.parent.conversationColored.WriteString(ansi.Blue + string(d.raw) + ansi.Reset + "\n[" + d.ac.GetCaptureInfo().Timestamp.String() + "]\n")
				} else {
					h.parent.conversationColored.WriteString(ansi.Blue + string(d.raw) + ansi.Reset)
				}
			}
		}
	}

	return h.parent.conversationRaw.Bytes()
}

func (h *httpReader) ConversationColored() []byte {
	h.parent.Lock()
	defer h.parent.Unlock()
	return h.parent.conversationColored.Bytes()
}

func (h *httpReader) IsClient() bool {
	return h.isClient
}

func (h *httpReader) Ident() string {
	return h.parent.ident
}
func (h *httpReader) Network() gopacket.Flow {
	return h.parent.net
}
func (h *httpReader) Transport() gopacket.Flow {
	return h.parent.transport
}
func (h *httpReader) FirstPacket() time.Time {
	return h.parent.firstPacket
}
func (h *httpReader) Saved() bool {
	h.parent.Lock()
	defer h.parent.Unlock()
	return h.saved
}

func (h *httpReader) NumBytes() int {
	h.parent.Lock()
	defer h.parent.Unlock()
	return h.numBytes
}

func (h *httpReader) Client() StreamReader {
	return h.parent.client.(StreamReader)
}

func (h *httpReader) SetClient(v bool) {
	h.parent.Lock()
	defer h.parent.Unlock()
	h.isClient = v
}

func (h *httpReader) MarkSaved() {
	h.parent.Lock()
	defer h.parent.Unlock()
	h.saved = true
}

func (h *httpReader) ServiceBanner() []byte {
	h.parent.Lock()
	defer h.parent.Unlock()

	if h.serviceBanner.Len() == 0 {
		// save server stream for banner identification
		// stores c.BannerSize number of bytes of the server side stream
		for _, d := range h.parent.server.DataSlice() {
			for _, b := range d.raw {
				h.serviceBanner.WriteByte(b)
				h.serviceBannerBytes++
				if h.serviceBannerBytes == c.BannerSize {
					break
				}
			}
		}
	}

	return h.serviceBanner.Bytes()
}