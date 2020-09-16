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

package decoder

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/dreadl0ck/cryptoutils"
	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/reassembly"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
)

const (
	headerContentType     = "Content-Type"
	headerContentEncoding = "Content-Encoding"

	methodPost = "POST"

	credentialsDecoderName = "Credentials"
)

// header is a HTTP header structure.
type header struct {
	name  string
	value string
}

// cookie is a HTTP cookie structure.
type cookie struct {
	name  string
	value string
}

// httpMetaStore is a thread safe in-memory store for interesting HTTP artifacts.
// TODO: currently not in use, make it configurable
type httpMetaStore struct {

	// mapped ip address to server names
	ServerNames map[string]string

	// mapped ip address to user agents
	UserAgents map[string]string

	// mapped ip address to user agents
	Vias map[string]string

	// mapped ip address to user agents
	XPoweredBy map[string]string

	// mapped ips to known header and cookies of frontend frameworks
	CMSHeaders map[string][]header
	CMSCookies map[string][]cookie

	sync.Mutex
}

// global store for selected http meta information
// TODO: add a util to dump.
var httpStore = &httpMetaStore{
	ServerNames: make(map[string]string),
	UserAgents:  make(map[string]string),
	Vias:        make(map[string]string),
	XPoweredBy:  make(map[string]string),
	CMSHeaders:  make(map[string][]header),
	CMSCookies:  make(map[string][]cookie),
}

/*
 * HTTP
 */

type httpRequest struct {
	request   *http.Request
	timestamp int64
	clientIP  string
	serverIP  string
}

type httpResponse struct {
	response  *http.Response
	timestamp int64
	clientIP  string
	serverIP  string
}

type httpReader struct {
	parent    *tcpConnection
	requests  []*httpRequest
	responses []*httpResponse
}

// Decode parses the stream according to the HTTP protocol.
func (h *httpReader) Decode() {
	// prevent nil pointer access if decoder is not initialized
	if httpDecoder.writer == nil {
		return
	}

	// parse conversation
	var (
		buf         bytes.Buffer
		previousDir reassembly.TCPFlowDirection
	)

	if len(h.parent.merged) > 0 {
		previousDir = h.parent.merged[0].dir
	}

	for _, d := range h.parent.merged {
		if d.dir == previousDir {
			buf.Write(d.raw)
		} else {
			var (
				err error
				b   = bufio.NewReader(&buf)
			)

			if previousDir == reassembly.TCPDirClientToServer {
				for !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
					err = h.readRequest(b)
				}
			} else {
				for !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
					err = h.readResponse(b)
				}
			}
			if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
				decoderLog.Error("error reading HTTP",
					zap.Error(err),
					zap.String("ident", h.parent.ident),
				)
			}
			buf.Reset()
			previousDir = d.dir

			buf.Write(d.raw)

			continue
		}
	}

	var (
		err error
		b   = bufio.NewReader(&buf)
	)

	if previousDir == reassembly.TCPDirClientToServer {
		for !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			err = h.readRequest(b)
		}
	} else {
		for !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			err = h.readResponse(b)
		}
	}
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		decoderLog.Error("error reading HTTP",
			zap.Error(err),
			zap.String("ident", h.parent.ident),
		)
	}

	// iterate over responses
	for _, res := range h.responses { // populate types.HTTP with all infos from response
		ht := newHTTPFromResponse(res.response)

		_ = h.findRequest(res.response)

		atomic.AddInt64(&stats.numResponses, 1)

		// now add request information
		if res.response.Request != nil {
			if isCustomDecoderLoaded(credentialsDecoderName) {
				h.searchForLoginParams(res.response.Request)
				h.searchForBasicAuth(res.response.Request)
			}

			atomic.AddInt64(&stats.numRequests, 1)
			setRequest(ht, &httpRequest{
				request:   res.response.Request,
				timestamp: res.timestamp,
				clientIP:  res.clientIP,
				serverIP:  res.serverIP,
			})
		} else {
			// response without matching request
			// don't add to output for now
			atomic.AddInt64(&stats.numUnmatchedResp, 1)

			continue
		}

		h.parent.writeHTTP(ht)
	}

	// iterate over unanswered requests
	for _, req := range h.requests {
		if req != nil {
			ht := &types.HTTP{}
			setRequest(ht, req)

			if isCustomDecoderLoaded(credentialsDecoderName) {
				h.searchForLoginParams(req.request)
				h.searchForBasicAuth(req.request)
			}

			atomic.AddInt64(&stats.numRequests, 1)
			atomic.AddInt64(&stats.numUnansweredRequests, 1)

			h.parent.writeHTTP(ht)
		} else {
			atomic.AddInt64(&stats.numNilRequests, 1)
		}
	}
}

// search request header field for HTTP basic auth.
func (h *httpReader) searchForBasicAuth(req *http.Request) {
	if u, p, ok := req.BasicAuth(); ok {
		if u != "" || p != "" {
			writeCredentials(&types.Credentials{
				Timestamp: h.parent.firstPacket.UnixNano(),
				Service:   "HTTP Basic Auth",
				Flow:      h.parent.ident,
				User:      u,
				Password:  p,
			})
		}
	}
}

// search for user name and password in http url params and body params.
func (h *httpReader) searchForLoginParams(req *http.Request) {
	for name, values := range req.Form {
		if !(name == "user" || name == "username") {
			continue
		}

		var (
			pass string
			arr  []string
			ok   bool
		)

		arr, ok = req.Form["pass"]
		if !ok {
			arr = req.Form["password"]
		}

		if len(arr) > 0 {
			pass = strings.Join(arr, "; ")
		}

		writeCredentials(&types.Credentials{
			Timestamp: h.parent.firstPacket.UnixNano(),
			Service:   serviceHTTP,
			Flow:      h.parent.ident,
			User:      strings.Join(values, "; "),
			Password:  pass,
			Notes:     "Login Parameters",
		})
	}
}

// populate the global http meta information store
// unused at the moment because too inefficient
func updateHTTPStore(h *types.HTTP) {
	// ------ LOCK the store
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
		var sn string
		if sn, ok = httpStore.Vias[h.DstIP]; ok {
			if !strings.Contains(sn, val) {
				httpStore.Vias[h.DstIP] = sn + "| " + val
			}
		} else {
			httpStore.Vias[h.DstIP] = val
		}
	}

	if val, ok := h.ResponseHeader["X-Powered-By"]; ok {
		var sn string
		if sn, ok = httpStore.XPoweredBy[h.DstIP]; ok {
			if !strings.Contains(sn, val) {
				httpStore.XPoweredBy[h.DstIP] = sn + "| " + val
			}
		} else {
			httpStore.XPoweredBy[h.DstIP] = val
		}
	}

	// Iterate over all response headers and check if they are known CMS headers.
	// If so, add them to the httpStore for the DstIP
	for key, val := range h.ResponseHeader {
		if _, ok := cmsHeaders[key]; ok {
			httpStore.CMSHeaders[h.DstIP] = append(httpStore.CMSHeaders[h.DstIP], header{name: key, value: val})
		}
	}

	// If HTTP instructions are sent to set a cookie used by CMSs (of other apps), add the key and possible value to the httpStore
	if toSet, ok := h.ResponseHeader["Set-Cookie"]; ok {
		var (
			parsedCookie = strings.Split(toSet, "=")
			cookieKey    = parsedCookie[0]
			cookieValue  string
		)
		if len(parsedCookie) > 1 {
			cookieValue = parsedCookie[1]
		}
		if _, ok = cmsCookies[cookieKey]; ok {
			httpStore.CMSCookies[h.DstIP] = append(httpStore.CMSCookies[h.DstIP], cookie{name: cookieKey, value: cookieValue})
		}
	}

	// ------ UNLOCK the store
	httpStore.Unlock()
}

func (t *tcpConnection) writeHTTP(h *types.HTTP) {

	// TODO: this kills performance
	//updateHTTPStore(h)

	if conf.IncludePayloads {
		h.RequestBody = t.client.DataSlice().bytes()
		h.ResponseBody = t.server.DataSlice().bytes()
	}

	// export metrics if configured
	if conf.ExportMetrics {
		h.Inc()
	}

	// write record to disk
	atomic.AddInt64(&httpDecoder.numRecords, 1)
	err := httpDecoder.writer.Write(h)
	if err != nil {
		errorMap.Inc(err.Error())
	}

	soft := whatSoftwareHTTP(t.ident, h)

	if len(soft) == 0 {
		return
	}

	writeSoftware(soft, func(s *software) {
		s.Lock()
		for _, f := range s.Flows {
			// prevent duplicates
			if f == t.ident {
				s.Unlock()
				return
			}
		}
		// add flow
		s.Flows = append(s.Flows, t.ident)
		s.Unlock()
	})
}

// HTTP Response

func (h *httpReader) readResponse(b *bufio.Reader) error {
	// try to read HTTP response from the buffered reader
	res, err := http.ReadResponse(b, nil)
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return err
	} else if err != nil {
		logReassemblyError("HTTP-response", h.parent.ident, err)
		return err
	}

	body, err := ioutil.ReadAll(res.Body)
	s := len(body)
	if err != nil {
		logReassemblyError("HTTP-response-body", fmt.Sprintf("%s: failed to get body(parsed len:%d)", h.parent.ident, s), err)
	} else {
		_ = res.Body.Close()

		// Restore body so it can be read again
		res.Body = ioutil.NopCloser(bytes.NewBuffer(body))
	}
	//if h.parent.hexdump {
	//	logReassemblyInfo("Body(%d/0x%x)\n%s\n", len(body), len(body), hex.Dump(body))
	//}

	sym := ","
	if res.ContentLength > 0 && res.ContentLength != int64(s) {
		sym = "!="
	}

	// determine content type for debug log
	contentType, ok := res.Header[headerContentType]
	if !ok {
		contentType = []string{http.DetectContentType(body)}
	}

	encoding := res.Header[headerContentEncoding]
	reassemblyLog.Debug("HTTP response",
		zap.String("ident", h.parent.ident),
		zap.String("Status", res.Status),
		zap.Int64("ContentLength", res.ContentLength),
		zap.String("sym", sym),
		zap.Int("bodyLength", s),
		zap.Strings("contentType", contentType),
		zap.Strings("encoding", encoding),
	)

	// increment counter
	stats.Lock()
	stats.responses++
	stats.Unlock()

	h.parent.Lock()
	h.responses = append(h.responses, &httpResponse{
		response:  res,
		timestamp: h.parent.firstPacket.UnixNano(),
		clientIP:  h.parent.net.Src().String(),
		serverIP:  h.parent.net.Dst().String(),
	})
	h.parent.Unlock()

	// write responses to disk if configured
	if (err == nil || conf.WriteIncomplete) && conf.FileStorage != "" {
		h.parent.Lock()
		var (
			name         = "unknown"
			source       = "HTTP RESPONSE"
			ctype        string
			numResponses = len(h.responses)
			numRequests  = len(h.requests)
		)
		h.parent.Unlock()

		// check if there is a matching request for the current stream
		if numRequests >= numResponses { // fetch it
			h.parent.Lock()
			req := h.requests[numResponses-1]
			h.parent.Unlock()
			if req != nil {
				name = path.Base(req.request.URL.Path)
				source += " from " + req.request.Host + req.request.URL.Path
				ctype = strings.Join(req.request.Header[headerContentType], " ")
			}
		}

		// save file to disk
		return h.saveFile(source, name, err, body, encoding, ctype)
	}

	return nil
}

func (h *httpReader) findRequest(res *http.Response) string {
	// try to find the matching HTTP request for the response
	var (
		req    *http.Request
		reqURL string
	)

	h.parent.Lock()
	if len(h.requests) != 0 {
		// take the request from the parent stream and delete it from there
		req, h.requests = h.requests[0].request, h.requests[1:]
		reqURL = req.URL.String()
	}
	h.parent.Unlock()

	// set request instance on response
	if req != nil {
		res.Request = req
		atomic.AddInt64(&stats.numFoundRequests, 1)
	}

	return reqURL
}

func trimEncoding(ctype string) string {
	parts := strings.Split(ctype, ";")
	if len(parts) > 1 {
		return parts[0]
	}
	return ctype
}

// keep track which paths for content types of extracted files have already been created.
var (
	contentTypeMap   = make(map[string]struct{})
	contentTypeMapMu sync.Mutex
)

// createContentTypePathIfRequired will create the passed in filesystem path once
// it is safe for concurrent access and will block until the path has been created on disk.
func createContentTypePathIfRequired(fsPath string) {
	contentTypeMapMu.Lock()
	if _, ok := contentTypeMap[fsPath]; !ok { // the path has not been created yet
		// add to map
		contentTypeMap[fsPath] = struct{}{}

		// create path
		err := os.MkdirAll(fsPath, defaults.DirectoryPermission)
		if err != nil {
			logReassemblyError("HTTP-create-path", fmt.Sprintf("cannot create folder %s", fsPath), err)
		}
	}
	// free lock again
	contentTypeMapMu.Unlock()
}

// TODO: write unit tests and cleanup.
func (h *httpReader) saveFile(source, name string, err error, body []byte, encoding []string, contentType string) error {
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
		root = path.Join(conf.FileStorage, ctype)

		// file extension
		ext = fileExtensionForContentType(ctype)

		// file basename
		base = filepath.Clean(name+"-"+path.Base(h.parent.ident)) + ext
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
	createContentTypePathIfRequired(root)

	// add base
	base = path.Join(root, base)
	if len(base) > 250 {
		base = base[:250] + "..."
	}
	if base == conf.FileStorage {
		base = path.Join(conf.FileStorage, "noname")
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
			target = path.Join(root, filepath.Clean("incomplete-"+name+"-"+h.parent.ident)+"-"+strconv.Itoa(n)+fileExtensionForContentType(ctype))
		} else {
			target = path.Join(root, filepath.Clean(name+"-"+h.parent.ident)+"-"+strconv.Itoa(n)+fileExtensionForContentType(ctype))
		}

		n++
	}

	decoderLog.Info("saving file", zap.String("target", target))

	f, err := os.Create(target)
	if err != nil {
		logReassemblyError("HTTP-create", fmt.Sprintf("cannot create %s", target), err)

		return err
	}

	var (
		// explicitly declare io.Reader interface
		r      io.Reader
		length int
		hash   string
	)

	// now assign a new buffer
	r = bytes.NewBuffer(body)
	if len(encoding) > 0 && (encoding[0] == "gzip" || encoding[0] == "deflate") {
		r, err = gzip.NewReader(r)
		if err != nil {
			logReassemblyError("HTTP-gunzip", "Failed to gzip decode: %s", err)
		}
	}

	if err == nil {
		var written int64
		written, err = io.Copy(f, r)

		if err != nil {
			logReassemblyError("HTTP-save", fmt.Sprintf("%s: failed to copy %s (l:%d)", h.parent.ident, target, written), err)
		}

		if _, ok := r.(*gzip.Reader); ok {
			err = r.(*gzip.Reader).Close()
			if err != nil {
				logReassemblyError("HTTP-save", fmt.Sprintf("%s: failed to close gzip reader %s (l:%d)", h.parent.ident, target, written), err)
			}
		}

		err = f.Close()
		if err != nil {
			logReassemblyError("HTTP-save", fmt.Sprintf("%s: failed to close %s (l:%d)", h.parent.ident, target, written), err)
		} else {
			reassemblyLog.Debug("saved HTTP data",
				zap.String("ident", h.parent.ident),
				zap.String("target", target),
				zap.Int64("written", written),
			)
		}

		var data []byte

		// TODO: refactor to avoid reading the file contents into memory again
		data, err = ioutil.ReadFile(target)
		if err == nil {
			// set hash to value for decompressed content and update size
			hash = hex.EncodeToString(cryptoutils.MD5Data(data))
			length = len(data)

			// save previous content type
			ctypeOld := ctype

			// update content type
			ctype = trimEncoding(http.DetectContentType(data))

			// make sure root path exists
			createContentTypePathIfRequired(path.Join(conf.FileStorage, ctype))

			// switch the file extension and the path for the updated content type
			ext = filepath.Ext(target)

			// create new target: trim extension from old one and replace
			// and replace the old content type in the path
			newTarget := strings.Replace(strings.TrimSuffix(target, ext), ctypeOld, ctype, 1) + fileExtensionForContentType(ctype)

			err = os.Rename(target, newTarget)
			if err == nil {
				target = newTarget
			} else {
				fmt.Println("failed to rename file after decompression", err)
			}
		}
	} else {
		hash = hex.EncodeToString(cryptoutils.MD5Data(body))
		length = len(body)
	}

	// write file to disk
	writeFile(&types.File{
		Timestamp:           h.parent.firstPacket.UnixNano(),
		Name:                fileName,
		Length:              int64(length),
		Hash:                hash,
		Location:            target,
		Ident:               h.parent.ident,
		Source:              source,
		ContentTypeDetected: ctype,
		ContentType:         contentType,
		SrcIP:               h.parent.net.Src().String(),
		DstIP:               h.parent.net.Dst().String(),
		SrcPort:             utils.DecodePort(h.parent.transport.Src().Raw()),
		DstPort:             utils.DecodePort(h.parent.transport.Dst().Raw()),
	})

	return nil
}

// HTTP Request

func (h *httpReader) readRequest(b *bufio.Reader) error {
	req, err := http.ReadRequest(b)
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return err
	} else if err != nil {
		logReassemblyError("HTTP-request", h.parent.ident, err)
		return err
	}

	body, err := ioutil.ReadAll(req.Body)
	s := len(body)
	if err != nil {
		logReassemblyError("HTTP-request-body", "Got body err: %s\n", err)
		// continue execution
	} else {
		_ = req.Body.Close()

		// Restore body so it can be read again
		req.Body = ioutil.NopCloser(bytes.NewBuffer(body))
	}
	//if h.tcpStreamReader.hexdump {
	//	logReassemblyInfo("Body(%d/0x%x)\n%s\n", len(body), len(body), hex.Dump(body))
	//}

	reassemblyLog.Debug("HTTP request",
		zap.String("ident", h.parent.ident),
		zap.String("method", req.Method),
		zap.String("url", req.URL.String()),
		zap.Int("bodyLength", s),
	)

	h.parent.Lock()
	t := h.parent.firstPacket.UnixNano()
	h.parent.Unlock()

	request := &httpRequest{
		request:   req,
		timestamp: t,
		clientIP:  h.parent.net.Src().String(),
		serverIP:  h.parent.net.Dst().String(),
	}

	// parse form values
	err = req.ParseForm()
	if err != nil {
		logReassemblyError("HTTP-request", fmt.Sprintf("%s: failed to parse form values", h.parent.ident), err)
	}

	// increase counter
	stats.Lock()
	stats.requests++
	stats.Unlock()

	h.parent.Lock()
	h.requests = append(h.requests, request)
	h.parent.Unlock()

	if req.Method == methodPost {
		// write request payload to disk if configured
		if (err == nil || conf.WriteIncomplete) && conf.FileStorage != "" {
			return h.saveFile("HTTP POST REQUEST to "+req.URL.Path, path.Base(req.URL.Path), err, body, req.Header[headerContentEncoding], strings.Join(req.Header[headerContentType], " "))
		}
	}

	return nil
}
