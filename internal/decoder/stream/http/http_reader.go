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
	backedBodyType string
	body           []byte
	bodyLoaded     bool
	pairable       bool
	evidence       messageEvidence
	incomplete     bool
	request        *http.Request
	timestamp      int64
	clientIP       string
	serverIP       string
	clientPort     int32
	serverPort     int32
	flow           string
	headerOrder    []string // Header names in wire order for JA4H
	cookieFields   []string // Cookie field names in order for JA4H
	acceptLang     string   // Accept-Language value for JA4H
}

type httpResponse struct {
	requestIndex        int
	body                []byte
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
	artifactRecovery    bool
	directionalEvidence [2]core.DataFragments
	bufferReleases      []func()
	conversation        *core.ConversationInfo

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
	sourceMode            bool
	sourceHeaderCredits   int64
}

// New constructs a new http stream decoder.
func (h *httpReader) New(conversation *core.ConversationInfo) core.StreamDecoderInterface {
	return &httpReader{
		conversation: conversation,
	}
}

// Decode parses the stream according to the HTTP protocol.
func (h *httpReader) Decode() {
	if h.conversation.Source != nil && h.conversation.Transport != core.UDP {
		if h.decodeSource() {
			return
		}
	}
	if h.conversation.Transport == core.UDP {
		for fragment := range h.conversation.Fragments() {
			conversation := *h.conversation
			conversation.Source = nil
			conversation.Data = core.DataFragments{fragment}
			conversation.ClientData, conversation.ServerData = nil, nil
			reader := &httpReader{conversation: &conversation}
			reader.decodeTransportRun()
			if h.writeError == nil {
				h.writeError = reader.writeError
			}
		}
		return
	}
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
	if !h.artifactRecovery && decoderconfig.Instance.FileStorage != "" {
		// Complete headers establish object framing before a TCP close. Preserve
		// contiguous body bytes observed after it as qualified artifact evidence,
		// without inventing an ordinary cross-close HTTP transaction.
		recovery := &httpReader{conversation: h.conversation, artifactRecovery: true, transportObservation: "cross-close-body"}
		recovery.decodeTransportRun()
	}
}

func (h *httpReader) decodeTransportRun() {
	defer func() {
		h.conversation.StateBudget.Release(h.sourceHeaderCredits)
		h.sourceHeaderCredits = 0
		for _, release := range h.bufferReleases {
			release()
		}
	}()
	// prevent nil pointer access if decoder is not initialized
	if Decoder.Writer == nil {
		return
	}

	h.decodeDirections()
	if h.conversation.FragmentError != nil {
		return
	}
	if h.artifactRecovery {
		return
	}

	// iterate over responses
	for _, res := range h.responses { // populate types.HTTP with all infos from response
		var ht *types.HTTP
		if res.transient {
			length := res.response.ContentLength
			if length < 0 {
				length = res.wireBytes
			}
			ht = httpResponseRecord(res.response, int32(min(length, int64(2147483647))), res.detectedContentType)
		} else {
			ht = httpFromResponseBody(res.response, res.body, nil)
		}
		ht.Timestamp, ht.Flow = res.timestamp, res.flow
		ht.SrcIP, ht.DstIP, ht.SrcPort, ht.DstPort = res.serverIP, res.clientIP, res.serverPort, res.clientPort

		matchedReq := h.findRequest(res)

		atomic.AddInt64(&streamutils.Stats.NumResponses, 1)

		// now add request information
		if matchedReq != nil && res.response.Request != nil {
			if secret.Decoder.Writer != nil && h.transportObservation == "" {
				h.searchForLoginParams(matchedReq)
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
				h.searchForLoginParams(req)
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
func (h *httpReader) searchForLoginParams(req *httpRequest) {
	for _, record := range secret.HTTPQuerySecrets(req.request.URL.Query(), h.conversation.Ident, req.timestamp) {
		record.CommunityID = h.conversation.CommunityID
		record.Method, record.Uri = req.request.Method, req.request.RequestURI
		secret.WriteSecret(record)
	}
	user, password, found := secret.HTTPFormCredentials(req.request.PostForm)
	if !found {
		return
	}
	secret.WriteSecret(&types.Secret{Timestamp: req.timestamp, Service: "HTTP", Flow: h.conversation.Ident, CommunityID: h.conversation.CommunityID, User: user, Password: password, Notes: "Login Parameters"})
}

func (h *httpReader) emitHTTP(record *types.HTTP) {
	if h.artifactRecovery {
		return
	}
	if h.conversation.TLSDecrypted {
		record.ParseQualifications = appendUnique(record.ParseQualifications, "decrypted-tls-key-log")
	}
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

	software.WriteHTTPSoftware(soft, ident, h.CommunityID)
	return nil
}

// HTTP Response

func (h *httpReader) readResponse(b *bufio.Reader, pos *streamutils.ReadPosition) error {
	// Taken before the response is consumed. Every response on a connection
	// used to carry FirstServerPacket, so a keep-alive connection serving
	// dozens of them reported one time for all of them.
	timestamp := pos.Timestamp()
	headerStart := pos.Offset()

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
	headerEnd := pos.Offset()

	var body []byte
	var spool *file.BodySpool
	var passiveReport webtech.Report
	observation := webtech.Observation{Status: res.StatusCode, ContentType: res.Header.Get(headerContentType), Generator: res.Header.Values("X-Generator")}
	authority := ""
	if request != nil {
		observation.Method = request.Method
		authority = request.Host
	}
	if decoderconfig.Instance.FileStorage == "" && !decoderconfig.Instance.IncludePayloads {
		passiveReport = software.ObserveWebtech(observation, res.Body, res.Header.Get(headerContentEncoding), authority, h.conversation.Ident, h.conversation.CommunityID, timestamp)
		err = passiveReport.WireError
	} else if h.sourceMode && !decoderconfig.Instance.IncludePayloads {
		if res.Body == http.NoBody {
			passiveReport = software.ObserveWebtech(observation, res.Body, res.Header.Get(headerContentEncoding), authority, h.conversation.Ident, h.conversation.CommunityID, timestamp)
			passiveReport.DetectedContentType = ""
			if res.Header.Get(headerContentEncoding) != "gzip" {
				passiveReport.DetectedContentType = http.DetectContentType(nil)
			}
		} else {
			spool, err = file.SpoolBody(res.Body)
		}
		if spool != nil {
			defer func() { file.RecordArtifactWriteError(spool.Close()) }()
			passiveReport = software.ObserveWebtech(observation, spool.Reader(), res.Header.Get(headerContentEncoding), authority, h.conversation.Ident, h.conversation.CommunityID, timestamp)
			passiveReport.WireBytes = spool.Size()
			passiveReport.DetectedContentType = sourceResponseContentType(h.conversation, spool, res.Header.Get(headerContentEncoding))
		}
	} else {
		var release func()
		body, release, err = file.ReadBody(res.Body)
		h.bufferReleases = append(h.bufferReleases, release)
		if !h.artifactRecovery {
			software.ObserveWebtech(observation, bytes.NewReader(body), res.Header.Get(headerContentEncoding), authority, h.conversation.Ident, h.conversation.CommunityID, timestamp)
		}
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
	// Close drains unread wire bytes. An incomplete body already stops this run.
	if err == nil {
		_ = res.Body.Close()
	}
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

	stateErr := h.conversation.FragmentError
	if stateErr == nil {
		stateErr = h.retainSourceHeaders(evidence, headerEnd-headerStart)
	}
	if stateErr != nil && (stateErr != core.ErrCompletionStateBudget || spool == nil) {
		return stateErr
	}
	requestIndex := h.responseRequestIndex
	if stateErr == nil {
		streamutils.Stats.Lock()
		streamutils.Stats.Responses++
		streamutils.Stats.Unlock()

		h.responses = append(h.responses, &httpResponse{
			requestIndex:        requestIndex,
			body:                body,
			evidence:            evidence,
			readIssue:           err != nil,
			transient:           !decoderconfig.Instance.IncludePayloads && (decoderconfig.Instance.FileStorage == "" || h.sourceMode),
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
		if res.StatusCode >= 200 || res.StatusCode == 101 {
			h.responseRequestIndex++
		}
	}

	// write responses to disk if configured
	if !evidence.unsafe && (err == nil || decoderconfig.Instance.WriteIncomplete) && decoderconfig.Instance.FileStorage != "" && (!h.artifactRecovery || !h.preface && h.crossCloseBody(true, headerStart, headerEnd, pos.Offset())) {

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
		if spool != nil {
			file.RecordExtractionIssue((&HTTPFileExtractor{}).extractSpool(artifactConversation(h.conversation, stateErr), spool, metadata, err))
			if stateErr != nil {
				return stateErr
			}
			return err
		}
		if err != nil {
			// The generic extractor interface cannot carry the body read error.
			file.RecordExtractionIssue((&HTTPFileExtractor{}).extractFile(h.conversation, body, metadata, err))
			return err
		}
		file.RecordExtractionIssue(extractor.ExtractFile(h.conversation, body, metadata))
	}

	if stateErr != nil {
		return stateErr
	}
	if evidence.unsafe {
		return evidence.framingError()
	}
	return err
}

func (h *httpReader) findRequest(res *httpResponse) *httpRequest {
	i := res.requestIndex
	if res.response.Request == nil || i >= len(h.requests) {
		return nil
	}
	req := h.requests[i]
	if req == nil || req.request != res.response.Request {
		return nil
	}
	if res.response.StatusCode >= 200 || res.response.StatusCode == http.StatusSwitchingProtocols {
		h.requests[i] = nil
	}
	atomic.AddInt64(&streamutils.Stats.NumFoundRequests, 1)
	return req
}

// HTTP Request

func (h *httpReader) readRequest(b *bufio.Reader, pos *streamutils.ReadPosition) error {
	priorCredits := h.sourceHeaderCredits
	// Taken before the request is consumed; see readResponse.
	requestTimestamp := pos.Timestamp()
	headerStart := pos.Offset()

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

	headerEnd := pos.Offset()
	var body []byte
	var release func()
	var bodyErr error
	var spool *file.BodySpool
	form, boundary := sourceBackedForm(req)
	backedGzip := h.sourceMode && req.Body != http.NoBody && req.Header.Get(headerContentEncoding) == "gzip"
	mode := requestBuffered
	if h.sourceMode {
		mode = sourceRequestMode(decoderconfig.Instance, req, form)
	}
	switch mode {
	case requestSpooled:
		spool, bodyErr = file.SpoolBody(req.Body)
		release = func() {}
		if spool != nil {
			defer func() { file.RecordArtifactWriteError(spool.Close()) }()
			body = spool.Prefix()
			if err := h.conversation.StateBudget.Reserve(int64(cap(body))); err != nil {
				h.conversation.FragmentError = err
				if err != core.ErrCompletionStateBudget {
					return err
				}
				body = nil
			} else {
				h.sourceHeaderCredits += int64(cap(body))
			}
		}
	case requestCappedSample:
		body, release, bodyErr = readCappedSourceRequestBody(h.conversation, req.Body)
	case requestSample:
		body, release, bodyErr = readSourceRequestBody(h.conversation, req.Body)
	default:
		body, release, bodyErr = file.ReadBody(req.Body)
	}
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
	if bodyErr == nil {
		_ = req.Body.Close()
	}
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
		body:         body,
		bodyLoaded:   true,
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
	if spool != nil && backedGzip && h.conversation.FragmentError == nil {
		request.backedBodyType, err = backedGzipRequestType(h.conversation, spool)
		if err != nil {
			h.conversation.FragmentError = err
			if err != core.ErrCompletionStateBudget {
				return err
			}
		}
	}

	// parse form values
	switch {
	case h.conversation.FragmentError != nil:
		// Skip form parsing after a refused content probe; the spool can still be saved.
	case spool != nil && form == "multipart/form-data":
		var queryErr error
		req.Form, queryErr = evidenceQuery(req.URL.RawQuery)
		err = errors.Join(queryErr, parseEvidenceMultipart(req, spool.Reader(), boundary, func(n int64) error {
			if err := h.conversation.StateBudget.Reserve(n); err != nil {
				h.conversation.FragmentError = err
				return err
			}
			h.sourceHeaderCredits += n
			return nil
		}))
	case spool != nil && form == "application/x-www-form-urlencoded":
		err = h.parseBackedURLEncodedForm(req, spool.Reader())
	case spool != nil && form == "application/json":
		err = h.parseBackedJSONForm(req, spool)
	default:
		err = parseEvidenceForm(req, body)
	}
	stateErr := h.conversation.FragmentError
	if stateErr == nil {
		stateErr = h.retainSourceHeaders(evidence, headerEnd-headerStart)
	}
	if stateErr != nil && (stateErr != core.ErrCompletionStateBudget || spool == nil) {
		return stateErr
	}
	if stateErr != nil {
		body, request.body = nil, nil
		req.Form, req.PostForm, req.Body = nil, nil, http.NoBody
		h.conversation.StateBudget.Release(h.sourceHeaderCredits - priorCredits)
		h.sourceHeaderCredits = priorCredits
	}
	if err != nil && stateErr == nil {
		request.evidence.issues = appendUnique(request.evidence.issues, "incomplete-request-form")
		httpLog.Error(
			"failed to read HTTP form values",
			zap.String("ident", h.conversation.Ident),
			zap.Error(err),
		)
	}
	req.Body = io.NopCloser(bytes.NewReader(body))

	if stateErr == nil {
		streamutils.Stats.Lock()
		streamutils.Stats.Requests++
		streamutils.Stats.Unlock()

		h.requests = append(h.requests, request)
		if h.transportObservation == "" {
			secret.HarvestHTTPNTLMIdentity(req.Header.Get("Authorization"), request.clientIP, request.serverIP, request.clientPort, request.serverPort, t, h.conversation.CommunityID)
		}
	}

	if req.Method == methodPOST {
		// write request payload to disk if configured
		if !evidence.unsafe && (bodyErr == nil || decoderconfig.Instance.WriteIncomplete) && decoderconfig.Instance.FileStorage != "" && (!h.artifactRecovery || !h.preface && h.crossCloseBody(false, headerStart, headerEnd, pos.Offset())) {
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
			if spool != nil {
				file.RecordExtractionIssue((&HTTPFileExtractor{}).extractSpool(artifactConversation(h.conversation, stateErr), spool, metadata, bodyErr))
				if stateErr != nil {
					return stateErr
				}
				return bodyErr
			}
			if bodyErr != nil {
				file.RecordExtractionIssue((&HTTPFileExtractor{}).extractFile(h.conversation, body, metadata, bodyErr))
				return bodyErr
			}
			file.RecordExtractionIssue(extractor.ExtractFile(h.conversation, body, metadata))
		}
	}

	if stateErr != nil {
		return stateErr
	}
	if evidence.unsafe {
		return evidence.framingError()
	}
	return bodyErr
}

// Preserve the run error when publishing a spool completed before metadata pressure.
func artifactConversation(c *core.ConversationInfo, stateErr error) *core.ConversationInfo {
	if stateErr != core.ErrCompletionStateBudget {
		return c
	}
	snapshot := *c
	snapshot.FragmentError = nil
	return &snapshot
}
