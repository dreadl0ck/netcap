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
	"net/http"
	"path"
	"slices"
	"strings"
	"sync/atomic"

	"go.uber.org/zap"

	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/file"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/secret"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/software"
	streamutils "github.com/dreadl0ck/netcap/internal/decoder/stream/utils"
	decoderutils "github.com/dreadl0ck/netcap/internal/decoder/utils"
	"github.com/dreadl0ck/netcap/internal/webtech"
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
	pairable     bool
	evidence     messageEvidence
	incomplete   bool
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
	evidence            messageEvidence
	readIssue           bool
	transient           bool
	detectedContentType string
	wireBytes           int64
	response            *http.Response
	timestamp           int64
	clientIP            string
	serverIP            string
	clientPort          int32
	serverPort          int32
	flow                string
}

type httpReader struct {
	bufferReleases []func()
	conversation   *core.ConversationInfo

	requests              []*httpRequest
	responses             []*httpResponse
	captureLoss           bool
	pairingQualification  string
	directionBroken       [2]bool
	preface               bool
	initialUnknown        bool
	responseRequestIndex  int
	transportObservation  string
	unobservedResponseEnd bool
	writeError            error
}

// New constructs a new http stream decoder.
func (h *httpReader) New(conversation *core.ConversationInfo) core.StreamDecoderInterface {
	return &httpReader{
		conversation: conversation,
	}
}

// Decode parses the stream according to the HTTP protocol.
func (h *httpReader) Decode() {
	runs := streamutils.TransportRuns(h.conversation)
	if len(runs) == 1 {
		h.transportObservation = runs[0].Observation
		h.decodeTransportRun()
		return
	}
	for _, run := range runs {
		reader := &httpReader{conversation: run.Conversation, transportObservation: run.Observation, unobservedResponseEnd: h.unobservedResponseEnd, captureLoss: h.captureLoss, directionBroken: h.directionBroken}
		reader.decodeTransportRun()
		if h.writeError == nil {
			h.writeError = reader.writeError
		}
	}
}

func (h *httpReader) decodeTransportRun() {
	defer func() {
		for _, release := range h.bufferReleases {
			release()
		}
	}()
	// prevent nil pointer access if decoder is not initialized
	if Decoder.Writer == nil {
		return
	}

	h.decodeDirections()

	// iterate over responses
	for _, res := range h.responses { // populate types.HTTP with all infos from response
		ht := newHTTPFromResponse(res.response)
		if res.transient {
			ht.ResContentTypeDetected = res.detectedContentType
			if res.response.ContentLength < 0 {
				ht.ResContentLength = int32(min(res.wireBytes, int64(2147483647)))
			}
		}
		ht.Timestamp, ht.Flow = res.timestamp, res.flow
		ht.SrcIP, ht.DstIP, ht.SrcPort, ht.DstPort = res.serverIP, res.clientIP, res.serverPort, res.clientPort

		matchedReq := h.findRequest(res.response)

		atomic.AddInt64(&streamutils.Stats.NumResponses, 1)

		// now add request information
		if matchedReq != nil && res.response.Request != nil {
			if secret.Decoder.Writer != nil && h.transportObservation == "" {
				h.searchForLoginParams(res.response.Request)
				h.searchForBasicAuth(res.response.Request)
			}

			atomic.AddInt64(&streamutils.Stats.NumRequests, 1)
			// Use the matched request which preserves JA4H header order info
			setRequest(ht, matchedReq)
		} else {
			// The request may precede the capture; retain the visible response.
			atomic.AddInt64(&streamutils.Stats.NumUnmatchedResp, 1)
		}

		// Set Community ID for cross-tool correlation
		ht.CommunityID = h.conversation.CommunityID
		ht.RawResponseLine, ht.ResponseHeaders = res.evidence.line, res.evidence.headers
		if res.evidence.unsafe {
			ht.ResContentTypeDetected = ""
		}
		ht.ParseQualifications = appendUnique(ht.ParseQualifications, res.evidence.issues...)
		for _, issue := range res.evidence.issues {
			addStatus(ht, issue)
		}
		if h.initialUnknown {
			addStatus(ht, "unknown-initial-stream-loss")
		}
		h.qualifyPairing(ht, matchedReq != nil)
		if res.readIssue {
			ht.ReassemblyStatus = strings.Trim(ht.ReassemblyStatus+",incomplete_response_body", ",")
		}
		connect := res.response.Request != nil && res.response.Request.Method == methodCONNECT && res.response.StatusCode >= 200 && res.response.StatusCode < 300
		if h.unobservedResponseEnd && !connect && res.response.ContentLength < 0 && len(res.response.TransferEncoding) == 0 {
			addStatus(ht, "response-end-not-observed")
		}
		h.emitHTTP(ht)
	}

	// iterate over unanswered requests
	for _, req := range h.requests {
		if req != nil {
			ht := &types.HTTP{}
			setRequest(ht, req)

			if secret.Decoder.Writer != nil && h.transportObservation == "" {
				h.searchForLoginParams(req.request)
				h.searchForBasicAuth(req.request)
			}

			atomic.AddInt64(&streamutils.Stats.NumRequests, 1)
			atomic.AddInt64(&streamutils.Stats.NumUnansweredRequests, 1)

			// Set Community ID for cross-tool correlation
			ht.CommunityID = h.conversation.CommunityID
			if h.initialUnknown {
				addStatus(ht, "unknown-initial-stream-loss")
			}
			h.qualifyPairing(ht, false)
			h.emitHTTP(ht)
		} else {
			atomic.AddInt64(&streamutils.Stats.NumNilRequests, 1)
		}
	}
}

func (h *httpReader) qualifyPairing(record *types.HTTP, paired bool) {
	if h.transportObservation != "" {
		note := streamutils.TransportQualification(h.transportObservation)
		record.ParseQualifications = appendUnique(record.ParseQualifications, note)
		addStatus(record, note)
	}
	if h.captureLoss {
		if paired {
			addStatus(record, "capture_loss_elsewhere")
		} else {
			addStatus(record, "unpaired_after_capture_loss")
		}
	}
	if h.preface {
		addStatus(record, "unpaired_after_protocol_preface")
	}
	if !paired {
		addStatus(record, h.pairingQualification)
	}
}

// search request header field for HTTP basic auth.
func (h *httpReader) searchForBasicAuth(req *http.Request) {
	if u, p, ok := req.BasicAuth(); ok {
		if u != "" || p != "" {
			secret.WriteSecret(&types.Secret{
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

		secret.WriteSecret(&types.Secret{
			Timestamp: h.conversation.FirstClientPacket.UnixNano(),
			Service:   "HTTP",
			Flow:      h.conversation.Ident,
			User:      strings.Join(values, "; "),
			Password:  pass,
			Notes:     "Login Parameters",
		})
	}
}

func (h *httpReader) emitHTTP(record *types.HTTP) {
	if err := writeHTTP(record, h.conversation.Ident); err != nil && h.writeError == nil {
		h.writeError = err
	}
}

func writeHTTP(h *types.HTTP, ident string) error {
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
	err := Decoder.Writer.Write(h)
	if err != nil {
		decoderutils.ErrorMap.Inc(err.Error())
		return err
	}
	atomic.AddInt64(&Decoder.NumRecordsWritten, 1)

	soft := software.WhatSoftwareHTTP(ident, h)

	if len(soft) == 0 {
		return nil
	}

	communityID := h.CommunityID
	software.WriteSoftware(soft, func(s *software.AtomicSoftware) {
		s.Lock()
		// Check if flow already exists
		flowExists := slices.Contains(s.Flows, ident)
		// Add flow if not exists
		if !flowExists {
			s.Flows = append(s.Flows, ident)
		}
		// Add community ID if not exists
		if communityID != "" {
			cidExists := slices.Contains(s.CommunityIDs, communityID)
			if !cidExists {
				s.CommunityIDs = append(s.CommunityIDs, communityID)
			}
		}
		s.Unlock()
	})
	return nil
}

// HTTP Response

func (h *httpReader) readResponse(b *bufio.Reader, pos *streamutils.ReadPosition) error {
	// Taken before the response is consumed. Every response on a connection
	// used to carry FirstServerPacket, so a keep-alive connection serving
	// dozens of them reported one time for all of them.
	timestamp := pos.Timestamp()

	// try to read HTTP response from the buffered reader
	var request *http.Request
	if h.transportObservation == "" && !h.directionBroken[1] && h.responseRequestIndex < len(h.requests) {
		candidate := h.requests[h.responseRequestIndex]
		if candidate.pairable {
			request = candidate.request
		}
	}
	res, evidence, err := readEvidenceResponse(b, request)
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

	var body []byte
	var passiveReport webtech.Report
	observation := webtech.Observation{Status: res.StatusCode, ContentType: res.Header.Get(headerContentType), Generator: res.Header.Values("X-Generator")}
	authority := ""
	if request != nil {
		observation.Method = request.Method
		authority = request.Host
	}
	if decoderconfig.Instance.FileStorage == "" && !decoderconfig.Instance.IncludePayloads {
		passiveReport = software.ObserveWebtech(observation, res.Body, res.Header.Get(headerContentEncoding), authority, h.conversation.Ident, h.conversation.CommunityID, timestamp)
	} else {
		var release func()
		body, release, err = file.ReadBody(res.Body)
		h.bufferReleases = append(h.bufferReleases, release)
		software.ObserveWebtech(observation, bytes.NewReader(body), res.Header.Get(headerContentEncoding), authority, h.conversation.Ident, h.conversation.CommunityID, timestamp)
	}
	file.RecordExtractionIssue(err)
	s := len(body)
	if err != nil {
		httpLog.Debug(
			"failed to read HTTP response body",
			zap.String("ident", h.conversation.Ident),
			zap.Error(err),
			zap.Int("length", s),
		)
	}
	_ = res.Body.Close()
	res.Body = io.NopCloser(bytes.NewReader(body))
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
		evidence:            evidence,
		readIssue:           err != nil,
		transient:           decoderconfig.Instance.FileStorage == "" && !decoderconfig.Instance.IncludePayloads,
		detectedContentType: passiveReport.DetectedContentType,
		wireBytes:           passiveReport.WireBytes,
		response:            res,
		timestamp:           timestamp,
		clientIP:            h.conversation.ClientIP,
		serverIP:            h.conversation.ServerIP,
		clientPort:          h.conversation.ClientPort,
		serverPort:          h.conversation.ServerPort,
		flow:                h.conversation.Ident,
	})
	requestIndex := h.responseRequestIndex
	if res.StatusCode >= 200 || res.StatusCode == 101 {
		h.responseRequestIndex++
	}

	// write responses to disk if configured
	if h.transportObservation == "" && !evidence.unsafe && (err == nil || decoderconfig.Instance.WriteIncomplete) && decoderconfig.Instance.FileStorage != "" {

		var (
			name        = "unknown"
			ctype       = res.Header.Get(headerContentType)
			numRequests = len(h.requests)
			host        string
			method      = ""
			statusCode  = res.StatusCode
			urlPath     = ""
		)

		// check if there is a matching request for the current stream
		if request != nil && numRequests > requestIndex { // fetch it

			req := h.requests[requestIndex]
			if req != nil {
				host = req.request.Host
				name = path.Base(req.request.URL.Path)
				method = req.request.Method
				urlPath = req.request.RequestURI
			}
		}

		// Use new file extraction framework
		extractor, ok := file.GetExtractor("HTTP")
		if !ok {
			httpLog.Error("HTTP file extractor not registered")
			return err
		}

		metadata := file.FileMetadata{
			Timestamp:      timestamp,
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
		if err != nil {
			// The generic extractor interface cannot carry the body read error.
			file.RecordExtractionIssue((&HTTPFileExtractor{}).extractFile(h.conversation, body, metadata, err))
			return err
		}
		file.RecordExtractionIssue(extractor.ExtractFile(h.conversation, body, metadata))
	}

	if evidence.unsafe {
		return evidence.framingError()
	}
	return err
}

func (h *httpReader) findRequest(res *http.Response) *httpRequest {
	for i, req := range h.requests {
		if req != nil && req.request == res.Request {
			if res.StatusCode >= 200 || res.StatusCode == http.StatusSwitchingProtocols {
				h.requests[i] = nil
			}
			atomic.AddInt64(&streamutils.Stats.NumFoundRequests, 1)
			return req
		}
	}
	return nil
}

// HTTP Request

func (h *httpReader) readRequest(b *bufio.Reader, pos *streamutils.ReadPosition) error {
	// Taken before the request is consumed; see readResponse.
	requestTimestamp := pos.Timestamp()

	// Extract header order for JA4H fingerprinting before parsing
	// We need to peek at the raw bytes to preserve header order
	headerOrder, cookieFields, acceptLang := extractHeaderOrderFromReader(b)

	req, evidence, err := readEvidenceRequest(b)
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

	body, release, bodyErr := file.ReadBody(req.Body)
	file.RecordExtractionIssue(bodyErr)
	h.bufferReleases = append(h.bufferReleases, release)
	s := len(body)
	if bodyErr != nil {
		httpLog.Error(
			"failed to read HTTP request body",
			zap.String("ident", h.conversation.Ident),
			zap.Error(bodyErr),
			zap.Int("length", s),
		)
		// continue execution
	}
	_ = req.Body.Close()
	req.Body = io.NopCloser(bytes.NewReader(body))
	//if h.tcpStreamReader.hexdump {
	//	logReassemblyInfo("Body(%d/0x%x)\n%s\n", len(body), len(body), hex.Dump(body))
	//}

	httpLog.Debug("HTTP request",
		zap.String("ident", h.conversation.Ident),
		zap.String("method", req.Method),
		zap.String("url", req.URL.String()),
		zap.Int("bodyLength", s),
	)

	t := requestTimestamp

	request := &httpRequest{
		pairable:     !h.directionBroken[0] && !evidence.unsafe && bodyErr == nil,
		evidence:     evidence,
		incomplete:   bodyErr != nil,
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
	err = parseEvidenceForm(req, body)
	if err != nil {
		httpLog.Error(
			"failed to read HTTP form values",
			zap.String("ident", h.conversation.Ident),
			zap.Error(err),
		)
	}
	req.Body = io.NopCloser(bytes.NewReader(body))

	// increase counter
	streamutils.Stats.Lock()
	streamutils.Stats.Requests++
	streamutils.Stats.Unlock()

	h.requests = append(h.requests, request)
	if h.transportObservation == "" {
		secret.HarvestHTTPNTLMIdentity(req.Header.Get("Authorization"), request.clientIP, request.serverIP, request.clientPort, request.serverPort, t, h.conversation.CommunityID)
	}

	if req.Method == methodPOST {
		// write request payload to disk if configured
		if h.transportObservation == "" && !evidence.unsafe && (bodyErr == nil || decoderconfig.Instance.WriteIncomplete) && decoderconfig.Instance.FileStorage != "" {
			// Use new file extraction framework
			extractor, ok := file.GetExtractor("HTTP")
			if !ok {
				httpLog.Error("HTTP file extractor not registered")
				return bodyErr
			}

			metadata := file.FileMetadata{
				Timestamp:      requestTimestamp,
				ConnectionUID:  h.conversation.Ident,
				FlowDirection:  "client_to_server",
				HTTPMethod:     methodPOST,
				HTTPStatusCode: 0, // Request doesn't have status code
				HTTPURL:        req.RequestURI,
				Filename:       path.Base(req.URL.Path),
				ContentType:    strings.Join(req.Header[headerContentType], " "),
				Host:           req.Host,
				Encoding:       req.Header[headerContentEncoding],
			}
			if bodyErr != nil {
				file.RecordExtractionIssue((&HTTPFileExtractor{}).extractFile(h.conversation, body, metadata, bodyErr))
				return bodyErr
			}
			file.RecordExtractionIssue(extractor.ExtractFile(h.conversation, body, metadata))
		}
	}

	if evidence.unsafe {
		return evidence.framingError()
	}
	return bodyErr
}
