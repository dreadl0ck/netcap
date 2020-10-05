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
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"path"
	"strings"
	"sync/atomic"

	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/types"
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

	decodeTCPConversation(
		h.parent,
		func(b *bufio.Reader) error {
			return h.readRequest(b)
		},
		func(b *bufio.Reader) error {
			return h.readResponse(b)
		},
	)

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

func (t *tcpConnection) writeHTTP(h *types.HTTP) {
	// TODO: this kills performance
	// updateHTTPStore(h)

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
			host         string
		)
		h.parent.Unlock()

		// check if there is a matching request for the current stream
		if numRequests >= numResponses { // fetch it
			h.parent.Lock()
			req := h.requests[numResponses-1]
			h.parent.Unlock()
			if req != nil {
				host = req.request.Host
				name = path.Base(req.request.URL.Path)
				source += " from " + req.request.Host + req.request.URL.Path
				ctype = strings.Join(req.request.Header[headerContentType], " ")
			}
		}

		// save file to disk
		return saveFile(h.parent, source, name, err, body, encoding, ctype, host)
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
			return saveFile(
				h.parent,
				"HTTP POST REQUEST to "+req.URL.Path,
				path.Base(req.URL.Path),
				err,
				body,
				req.Header[headerContentEncoding],
				strings.Join(req.Header[headerContentType], " "),
				req.Host,
			)
		}
	}

	return nil
}
