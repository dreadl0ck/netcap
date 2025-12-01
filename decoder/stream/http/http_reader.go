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
	"github.com/dreadl0ck/netcap/decoder/stream/file"
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
	request      *http.Request
	timestamp    int64
	clientIP     string
	serverIP     string
	clientPort   int32
	serverPort   int32
	flow         string
	headerOrder  []string // Header names in wire order for JA4H
	cookieFields []string // Cookie field names in order for JA4H
	acceptLang   string   // Accept-Language value for JA4H
}

type httpResponse struct {
	response   *http.Response
	timestamp  int64
	clientIP   string
	serverIP   string
	clientPort int32
	serverPort int32
	flow       string
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

		matchedReq := h.findRequest(res.response)

		atomic.AddInt64(&streamutils.Stats.NumResponses, 1)

		// now add request information
		if matchedReq != nil && res.response.Request != nil {
			if credentials.Decoder.Writer != nil {
				h.searchForLoginParams(res.response.Request)
				h.searchForBasicAuth(res.response.Request)
			}

			atomic.AddInt64(&streamutils.Stats.NumRequests, 1)
			// Use the matched request which preserves JA4H header order info
			setRequest(ht, &httpRequest{
				request:      res.response.Request,
				timestamp:    res.timestamp,
				clientIP:     res.clientIP,
				serverIP:     res.serverIP,
				clientPort:   res.clientPort,
				serverPort:   res.serverPort,
				flow:         res.flow,
				headerOrder:  matchedReq.headerOrder,
				cookieFields: matchedReq.cookieFields,
				acceptLang:   matchedReq.acceptLang,
			})
		} else {
			// response without matching request
			// don't add to output for now
			atomic.AddInt64(&streamutils.Stats.NumUnmatchedResp, 1)

			continue
		}

		// Set Community ID for cross-tool correlation
		ht.CommunityID = h.conversation.CommunityID
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

			// Set Community ID for cross-tool correlation
			ht.CommunityID = h.conversation.CommunityID
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

	communityID := h.CommunityID
	software.WriteSoftware(soft, func(s *software.AtomicSoftware) {
		s.Lock()
		// Check if flow already exists
		flowExists := false
		for _, f := range s.Flows {
			if f == ident {
				flowExists = true
				break
			}
		}
		// Add flow if not exists
		if !flowExists {
			s.Flows = append(s.Flows, ident)
		}
		// Add community ID if not exists
		if communityID != "" {
			cidExists := false
			for _, cid := range s.CommunityIDs {
				if cid == communityID {
					cidExists = true
					break
				}
			}
			if !cidExists {
				s.CommunityIDs = append(s.CommunityIDs, communityID)
			}
		}
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
		response:   res,
		timestamp:  h.conversation.FirstServerPacket.UnixNano(),
		clientIP:   h.conversation.ClientIP,
		serverIP:   h.conversation.ServerIP,
		clientPort: h.conversation.ClientPort,
		serverPort: h.conversation.ServerPort,
		flow:       h.conversation.Ident,
	})

	// write responses to disk if configured
	if (err == nil || decoderconfig.Instance.WriteIncomplete) && decoderconfig.Instance.FileStorage != "" {

		var (
			name         = "unknown"
			ctype        string
			numResponses = len(h.responses)
			numRequests  = len(h.requests)
			host         string
			method       = ""
			statusCode   = res.StatusCode
			urlPath      = ""
		)

		// check if there is a matching request for the current stream
		if numRequests >= numResponses { // fetch it

			req := h.requests[numResponses-1]
			if req != nil {
				host = req.request.Host
				name = path.Base(req.request.URL.Path)
				method = req.request.Method
				urlPath = req.request.URL.Path
				ctype = strings.Join(req.request.Header[headerContentType], " ")
			}
		}

		// Use new file extraction framework
		extractor, ok := file.GetExtractor("HTTP")
		if !ok {
			httpLog.Error("HTTP file extractor not registered")
			return nil
		}

		metadata := file.FileMetadata{
			ConnectionUID:  h.conversation.Ident,
			FlowDirection:  "server_to_client",
			HTTPMethod:     method,
			HTTPStatusCode: statusCode,
			HTTPURL:        urlPath,
			Filename:       name,
			ContentType:    ctype,
			Host:           host,
			Encoding:       encoding,
		}
		return extractor.ExtractFile(h.conversation, body, metadata)
	}

	return nil
}

func (h *httpReader) findRequest(res *http.Response) *httpRequest {
	// try to find the matching HTTP request for the response
	var httpReq *httpRequest

	if len(h.requests) != 0 {
		// take the request from the parent stream and delete it from there
		httpReq, h.requests = h.requests[0], h.requests[1:]
	}

	// set request instance on response
	if httpReq != nil {
		res.Request = httpReq.request
		atomic.AddInt64(&streamutils.Stats.NumFoundRequests, 1)
	}

	return httpReq
}

// HTTP Request

func (h *httpReader) readRequest(b *bufio.Reader) error {
	// Extract header order for JA4H fingerprinting before parsing
	// We need to peek at the raw bytes to preserve header order
	headerOrder, cookieFields, acceptLang := extractHeaderOrderFromReader(b)

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
		request:      req,
		timestamp:    t,
		clientIP:     h.conversation.ClientIP,
		serverIP:     h.conversation.ServerIP,
		clientPort:   h.conversation.ClientPort,
		serverPort:   h.conversation.ServerPort,
		flow:         h.conversation.Ident,
		headerOrder:  headerOrder,
		cookieFields: cookieFields,
		acceptLang:   acceptLang,
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
			// Use new file extraction framework
			extractor, ok := file.GetExtractor("HTTP")
			if !ok {
				httpLog.Error("HTTP file extractor not registered")
				return nil
			}

			metadata := file.FileMetadata{
				ConnectionUID:  h.conversation.Ident,
				FlowDirection:  "client_to_server",
				HTTPMethod:     methodPOST,
				HTTPStatusCode: 0, // Request doesn't have status code
				HTTPURL:        req.URL.Path,
				Filename:       path.Base(req.URL.Path),
				ContentType:    strings.Join(req.Header[headerContentType], " "),
				Host:           req.Host,
				Encoding:       req.Header[headerContentEncoding],
			}
			return extractor.ExtractFile(h.conversation, body, metadata)
		}
	}

	return nil
}

// extractHeaderOrderFromReader extracts HTTP header order from a bufio.Reader
// by peeking at the raw bytes before http.ReadRequest consumes them.
// This is needed for JA4H fingerprinting which requires header order preservation.
func extractHeaderOrderFromReader(b *bufio.Reader) (headerOrder []string, cookieFields []string, acceptLang string) {
	// Try to peek enough bytes to see the headers
	// HTTP headers typically end with \r\n\r\n
	// We'll peek progressively larger amounts until we find the header end
	
	peekSizes := []int{1024, 4096, 8192, 16384, 32768}
	var peeked []byte
	
	for _, size := range peekSizes {
		data, err := b.Peek(size)
		if err != nil && len(data) == 0 {
			// Can't peek, return empty
			return nil, nil, ""
		}
		peeked = data
		
		// Check if we have the complete headers (ends with \r\n\r\n or \n\n)
		if bytes.Contains(peeked, []byte("\r\n\r\n")) || bytes.Contains(peeked, []byte("\n\n")) {
			break
		}
		
		// If we got less than requested, we've read all available data
		if len(data) < size {
			break
		}
	}
	
	if len(peeked) == 0 {
		return nil, nil, ""
	}
	
	// Find the end of headers
	headerEnd := bytes.Index(peeked, []byte("\r\n\r\n"))
	if headerEnd == -1 {
		headerEnd = bytes.Index(peeked, []byte("\n\n"))
		if headerEnd == -1 {
			headerEnd = len(peeked)
		}
	}
	
	headerBytes := peeked[:headerEnd]
	lines := bytes.Split(headerBytes, []byte("\n"))
	
	// Skip the request line (first line)
	for i := 1; i < len(lines); i++ {
		line := bytes.TrimRight(lines[i], "\r")
		if len(line) == 0 {
			continue
		}
		
		colonIdx := bytes.Index(line, []byte(":"))
		if colonIdx <= 0 {
			continue
		}
		
		headerName := string(bytes.TrimSpace(line[:colonIdx]))
		headerValue := string(bytes.TrimSpace(line[colonIdx+1:]))
		
		headerOrder = append(headerOrder, headerName)
		
		// Extract cookie field names
		if strings.EqualFold(headerName, "Cookie") {
			cookieFields = parseCookieFieldNamesFromValue(headerValue)
		}
		
		// Extract Accept-Language
		if strings.EqualFold(headerName, "Accept-Language") {
			acceptLang = headerValue
		}
	}
	
	return headerOrder, cookieFields, acceptLang
}

// parseCookieFieldNamesFromValue extracts cookie field names from a Cookie header value
func parseCookieFieldNamesFromValue(cookieValue string) []string {
	var fields []string
	
	pairs := strings.Split(cookieValue, ";")
	for _, pair := range pairs {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		
		eqIdx := strings.Index(pair, "=")
		if eqIdx > 0 {
			fields = append(fields, strings.TrimSpace(pair[:eqIdx]))
		} else if eqIdx == -1 {
			// Cookie without value
			fields = append(fields, pair)
		}
	}
	
	return fields
}
