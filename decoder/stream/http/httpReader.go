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
	"bufio"
	"bytes"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"path"
	"strings"
	"sync/atomic"

	"go.uber.org/zap"

	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/core"
	"github.com/dreadl0ck/netcap/decoder/stream/credentials"
	"github.com/dreadl0ck/netcap/decoder/stream/software"
	streamutils "github.com/dreadl0ck/netcap/decoder/stream/utils"
	decoderutils "github.com/dreadl0ck/netcap/decoder/utils"
	"github.com/dreadl0ck/netcap/types"
)

const (
	headerContentType     = "Content-Type"
	headerContentEncoding = "Content-Encoding"

	methodCONNECT = "CONNECT"
	methodDELETE  = "DELETE"
	methodGET     = "GET"
	methodHEAD    = "HEAD"
	methodOPTIONS = "OPTIONS"
	methodPATCH   = "PATCH"
	methodPOST    = "POST"
	methodPUT     = "PUT"
	methodTRACE   = "TRACE"
)

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
	conversation *core.ConversationInfo

	requests  []*httpRequest
	responses []*httpResponse
}

// New constructs a new http stream decoder.
func (h *httpReader) New(conversation *core.ConversationInfo) core.StreamDecoderInterface {
	return &httpReader{
		conversation: conversation,
	}
}

// Decode parses the stream according to the HTTP protocol.
func (h *httpReader) Decode() {
	// prevent nil pointer access if decoder is not initialized
	if Decoder.Writer == nil {
		return
	}

	streamutils.DecodeConversation(
		h.conversation.Ident,
		h.conversation.Data,
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

		atomic.AddInt64(&streamutils.Stats.NumResponses, 1)

		// now add request information
		if res.response.Request != nil {
			if credentials.Decoder.Writer != nil {
				h.searchForLoginParams(res.response.Request)
				h.searchForBasicAuth(res.response.Request)
			}

			atomic.AddInt64(&streamutils.Stats.NumRequests, 1)
			setRequest(ht, &httpRequest{
				request:   res.response.Request,
				timestamp: res.timestamp,
				clientIP:  res.clientIP,
				serverIP:  res.serverIP,
			})
		} else {
			// response without matching request
			// don't add to output for now
			atomic.AddInt64(&streamutils.Stats.NumUnmatchedResp, 1)

			continue
		}

		writeHTTP(ht, h.conversation.Ident)
	}

	// iterate over unanswered requests
	for _, req := range h.requests {
		if req != nil {
			ht := &types.HTTP{}
			setRequest(ht, req)

			if credentials.Decoder.Writer != nil {
				h.searchForLoginParams(req.request)
				h.searchForBasicAuth(req.request)
			}

			atomic.AddInt64(&streamutils.Stats.NumRequests, 1)
			atomic.AddInt64(&streamutils.Stats.NumUnansweredRequests, 1)

			writeHTTP(ht, h.conversation.Ident)
		} else {
			atomic.AddInt64(&streamutils.Stats.NumNilRequests, 1)
		}
	}
}

// search request header field for HTTP basic auth.
func (h *httpReader) searchForBasicAuth(req *http.Request) {
	if u, p, ok := req.BasicAuth(); ok {
		if u != "" || p != "" {
			credentials.WriteCredentials(&types.Credentials{
				Timestamp: h.conversation.FirstClientPacket.UnixNano(),
				Service:   "HTTP Basic Auth",
				Flow:      h.conversation.Ident,
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

		credentials.WriteCredentials(&types.Credentials{
			Timestamp: h.conversation.FirstClientPacket.UnixNano(),
			Service:   "HTTP",
			Flow:      h.conversation.Ident,
			User:      strings.Join(values, "; "),
			Password:  pass,
			Notes:     "Login Parameters",
		})
	}
}

func writeHTTP(h *types.HTTP, ident string) {
	// TODO: this kills performance, make configurable
	// updateHTTPStore(h)

	if decoderconfig.Instance.IncludePayloads {
		// TODO: only include request body, not the entire stream contents...
		// h.RequestBody = t.client.DataSlice().bytes()
		// h.ResponseBody = t.server.DataSlice().bytes()
	}

	// export metrics if configured
	if decoderconfig.Instance.ExportMetrics {
		h.Inc()
	}

	// write record to disk
	atomic.AddInt64(&Decoder.NumRecordsWritten, 1)
	err := Decoder.Writer.Write(h)
	if err != nil {
		decoderutils.ErrorMap.Inc(err.Error())
	}

	soft := software.WhatSoftwareHTTP(ident, h)

	if len(soft) == 0 {
		return
	}

	software.WriteSoftware(soft, func(s *software.AtomicSoftware) {
		s.Lock()
		for _, f := range s.Flows {
			// prevent duplicates
			if f == ident {
				s.Unlock()
				return
			}
		}
		// add flow
		s.Flows = append(s.Flows, ident)
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
		httpLog.Debug(
			"failed to read HTTP response",
			zap.String("ident", h.conversation.Ident),
			zap.Error(err),
		)
		return err
	}

	body, err := ioutil.ReadAll(res.Body)
	s := len(body)
	if err != nil {
		httpLog.Debug(
			"failed to read HTTP response body",
			zap.String("ident", h.conversation.Ident),
			zap.Error(err),
			zap.Int("length", s),
		)
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
	httpLog.Debug("HTTP response",
		zap.String("ident", h.conversation.Ident),
		zap.String("Status", res.Status),
		zap.Int64("ContentLength", res.ContentLength),
		zap.String("sym", sym),
		zap.Int("bodyLength", s),
		zap.Strings("contentType", contentType),
		zap.Strings("encoding", encoding),
	)

	// increment counter
	streamutils.Stats.Lock()
	streamutils.Stats.Responses++
	streamutils.Stats.Unlock()

	h.responses = append(h.responses, &httpResponse{
		response:  res,
		timestamp: h.conversation.FirstServerPacket.UnixNano(),
		clientIP:  h.conversation.ClientIP,
		serverIP:  h.conversation.ServerIP,
	})

	// write responses to disk if configured
	if (err == nil || decoderconfig.Instance.WriteIncomplete) && decoderconfig.Instance.FileStorage != "" {

		var (
			name         = "unknown"
			source       = "HTTP RESPONSE"
			ctype        string
			numResponses = len(h.responses)
			numRequests  = len(h.requests)
			host         string
		)

		// check if there is a matching request for the current stream
		if numRequests >= numResponses { // fetch it

			req := h.requests[numResponses-1]
			if req != nil {
				host = req.request.Host
				name = path.Base(req.request.URL.Path)
				source += " from " + req.request.Host + req.request.URL.Path
				ctype = strings.Join(req.request.Header[headerContentType], " ")
			}
		}

		// save file to disk
		return streamutils.SaveFile(h.conversation, source, name, err, body, encoding, host, ctype)
	}

	return nil
}

func (h *httpReader) findRequest(res *http.Response) string {
	// try to find the matching HTTP request for the response
	var (
		req    *http.Request
		reqURL string
	)

	if len(h.requests) != 0 {
		// take the request from the parent stream and delete it from there
		req, h.requests = h.requests[0].request, h.requests[1:]
		reqURL = req.URL.String()
	}

	// set request instance on response
	if req != nil {
		res.Request = req
		atomic.AddInt64(&streamutils.Stats.NumFoundRequests, 1)
	}

	return reqURL
}

// HTTP Request

func (h *httpReader) readRequest(b *bufio.Reader) error {
	req, err := http.ReadRequest(b)
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return err
	} else if err != nil {
		httpLog.Error(
			"failed to read HTTP request",
			zap.String("ident", h.conversation.Ident),
			zap.Error(err),
		)
		return err
	}

	body, err := ioutil.ReadAll(req.Body)
	s := len(body)
	if err != nil {
		httpLog.Error(
			"failed to read HTTP request body",
			zap.String("ident", h.conversation.Ident),
			zap.Error(err),
			zap.Int("length", s),
		)
		// continue execution
	} else {
		_ = req.Body.Close()

		// Restore body so it can be read again
		req.Body = ioutil.NopCloser(bytes.NewBuffer(body))
	}
	//if h.tcpStreamReader.hexdump {
	//	logReassemblyInfo("Body(%d/0x%x)\n%s\n", len(body), len(body), hex.Dump(body))
	//}

	httpLog.Debug("HTTP request",
		zap.String("ident", h.conversation.Ident),
		zap.String("method", req.Method),
		zap.String("url", req.URL.String()),
		zap.Int("bodyLength", s),
	)

	t := h.conversation.FirstClientPacket.UnixNano()

	request := &httpRequest{
		request:   req,
		timestamp: t,
		clientIP:  h.conversation.ClientIP,
		serverIP:  h.conversation.ServerIP,
	}

	// parse form values
	err = req.ParseForm()
	if err != nil {
		httpLog.Error(
			"failed to read HTTP form values",
			zap.String("ident", h.conversation.Ident),
			zap.Error(err),
		)
	}

	// increase counter
	streamutils.Stats.Lock()
	streamutils.Stats.Requests++
	streamutils.Stats.Unlock()

	h.requests = append(h.requests, request)

	if req.Method == methodPOST {
		// write request payload to disk if configured
		if (err == nil || decoderconfig.Instance.WriteIncomplete) && decoderconfig.Instance.FileStorage != "" {
			return streamutils.SaveFile(
				h.conversation,
				"HTTP POST REQUEST to "+req.URL.Path,
				path.Base(req.URL.Path),
				err,
				body,
				req.Header[headerContentEncoding],
				req.Host,
				strings.Join(req.Header[headerContentType], " "),
			)
		}
	}

	return nil
}
