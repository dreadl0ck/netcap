package http

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"

	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/file"
	streamutils "github.com/dreadl0ck/netcap/internal/decoder/stream/utils"
	"github.com/dreadl0ck/netcap/types"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type h2Message struct {
	headers, trailers []*types.HTTPHeaderEvidence
	body              []byte
	length            int64
	timestamp         int64
	started, ended    bool
}

type h2Transaction struct {
	id      uint32
	message [2]h2Message
	issues  []string
	upgrade *httpRequest
}

type h2Direction struct {
	wire                    *h2Wire
	framer                  *http2.Framer
	decoder                 *hpack.Decoder
	next                    http2.Frame
	timestamp               int64
	done, started           bool
	maxFrame                uint32
	blockID, promiseID      uint32
	blockEnd                bool
	blockTimestamp          int64
	blockBytes, headerBytes int
	fields                  []*types.HTTPHeaderEvidence
}

type h2Connection struct {
	reader                *httpReader
	direction             [2]*h2Direction
	streams               map[uint32]*h2Transaction
	closed                map[uint32]bool
	issues                []string
	lastRequest, lastPush uint32
	bodies, headers       int
	frames, transactions  int
	firstTimestamp        int64
	stopped               bool
}

func (h *httpReader) decodeH2(fragments [2]core.DataFragments, upgrade *httpRequest) {
	c := &h2Connection{reader: h, streams: make(map[uint32]*h2Transaction), closed: make(map[uint32]bool)}
	for side := range c.direction {
		d := &h2Direction{wire: &h2Wire{fragments: fragments[side]}, maxFrame: 16384}
		d.framer = http2.NewFramer(nil, d.wire)
		d.framer.SetMaxReadFrameSize(h2MaxFrame)
		d.decoder = hpack.NewDecoder(4096, func(field hpack.HeaderField) {
			d.headerBytes += len(field.Name) + len(field.Value) + 32
			if d.headerBytes > maxHTTPHeaders || len(d.fields) >= maxHTTPHeaderCount {
				d.decoder.SetEmitEnabled(false)
				return
			}
			d.fields = append(d.fields, &types.HTTPHeaderEvidence{Name: []byte(field.Name), Value: []byte(field.Value)})
		})
		d.decoder.SetMaxStringLength(maxHTTPHeaders)
		c.direction[side] = d
	}
	c.firstTimestamp = c.direction[0].wire.timestamp()
	if upgrade != nil {
		s := c.stream(1)
		s.upgrade = upgrade
		s.message[0] = h2Message{started: true, ended: true, timestamp: upgrade.timestamp}
		c.lastRequest = 1
		settings, _ := upgradeSettings(upgrade.request)
		for _, setting := range settings {
			c.setting(0, setting)
		}
	}
	preface := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(c.direction[0].wire, preface); err != nil || string(preface) != http2.ClientPreface {
		c.issues = append(c.issues, "h2-missing-client-preface")
		c.finish()
		return
	}
	for side := range c.direction {
		c.next(side)
	}
	tie := 0
	for !c.stopped {
		a, b := c.direction[0], c.direction[1]
		if a.next == nil && b.next == nil {
			break
		}
		side := 0
		if a.next == nil || b.next != nil && (b.timestamp < a.timestamp || b.timestamp == a.timestamp && tie == 1) {
			side = 1
		}
		tie = 1 - side
		d := c.direction[side]
		c.frames++
		if c.frames > h2MaxFrames {
			c.fail("h2-frame-count-limit")
			break
		}
		c.frame(side, d.next, d.timestamp)
		d.next = nil
		if !c.stopped {
			c.next(side)
		}
	}
	c.finish()
}

func (c *h2Connection) fail(issue string) {
	c.issues = appendUnique(c.issues, issue)
	c.stopped = true
}

func (c *h2Connection) next(side int) {
	d := c.direction[side]
	if d.done {
		return
	}
	d.timestamp = d.wire.timestamp()
	frame, err := d.framer.ReadFrame()
	if err != nil {
		d.done = true
		if !errors.Is(err, io.EOF) || d.blockID != 0 {
			issue := "h2-invalid-or-truncated-frame"
			if errors.Is(err, errH2Gap) {
				issue = "h2-capture-gap"
			}
			c.issues = appendUnique(c.issues, fmt.Sprintf("%s-direction-%d", issue, side))
		}
		return
	}
	d.next = frame
}

func (c *h2Connection) stream(id uint32) *h2Transaction {
	if s := c.streams[id]; s != nil {
		return s
	}
	_, closed := c.closed[id]
	if id == 0 || closed {
		c.fail("h2-closed-or-invalid-stream")
		return nil
	}
	if len(c.streams) >= h2MaxStreams || c.transactions >= h2MaxTransactions {
		c.fail("h2-stream-limit")
		return nil
	}
	s := &h2Transaction{id: id}
	c.streams[id] = s
	c.transactions++
	return s
}

func (c *h2Connection) setting(side int, setting http2.Setting) {
	if setting.Valid() != nil {
		c.fail("h2-invalid-settings")
		return
	}
	peer := c.direction[1-side]
	switch setting.ID {
	case http2.SettingHeaderTableSize:
		peer.decoder.SetAllowedMaxDynamicTableSize(min(setting.Val, h2MaxTable))
	case http2.SettingMaxFrameSize:
		peer.maxFrame = min(setting.Val, h2MaxFrame)
	case http2.SettingEnablePush:
		if side == 1 {
			c.fail("h2-server-enable-push")
		}
	}
}

func (c *h2Connection) frame(side int, frame http2.Frame, timestamp int64) {
	d := c.direction[side]
	if frame.Header().Length > d.maxFrame {
		c.fail("h2-frame-size-limit")
		return
	}
	if !d.started {
		settings, ok := frame.(*http2.SettingsFrame)
		if !ok || settings.IsAck() {
			c.fail("h2-missing-initial-settings")
			return
		}
		d.started = true
	}
	switch f := frame.(type) {
	case *http2.SettingsFrame:
		if !f.IsAck() {
			_ = f.ForeachSetting(func(s http2.Setting) error { c.setting(side, s); return nil })
		}
	case *http2.HeadersFrame:
		if f.StreamID%2 == 0 && c.streams[f.StreamID] == nil {
			c.fail("h2-unpromised-stream")
			return
		}
		d.blockID, d.blockEnd, d.blockTimestamp = f.StreamID, f.StreamEnded(), timestamp
		if _, closed := c.closed[f.StreamID]; !closed && c.stream(f.StreamID) == nil {
			return
		}
		c.headerFragment(side, f.HeaderBlockFragment(), f.HeadersEnded())
	case *http2.PushPromiseFrame:
		if side != 1 || f.PromiseID%2 != 0 || f.PromiseID <= c.lastPush || c.streams[f.StreamID] == nil {
			c.fail("h2-invalid-push-promise")
			return
		}
		c.lastPush = f.PromiseID
		d.blockID, d.promiseID, d.blockEnd, d.blockTimestamp = f.StreamID, f.PromiseID, true, timestamp
		c.headerFragment(side, f.HeaderBlockFragment(), f.HeadersEnded())
	case *http2.ContinuationFrame:
		c.headerFragment(side, f.HeaderBlockFragment(), f.HeadersEnded())
	case *http2.DataFrame:
		if reset, closed := c.closed[f.StreamID]; closed && !reset {
			c.issues = appendUnique(c.issues, "h2-in-flight-data-after-reset")
			return
		}
		s := c.streams[f.StreamID]
		if s == nil || !s.message[side].started || s.message[side].ended {
			c.fail("h2-data-without-open-message")
			return
		}
		m := &s.message[side]
		if side == 1 && len(f.Data()) > 0 && h2ResponseHasNoBody(s) {
			s.issues = appendUnique(s.issues, "h2-data-on-bodyless-response")
		}
		m.length += int64(len(f.Data()))
		keep := min(len(f.Data()), h2MaxBody-len(m.body), h2MaxBodies-c.bodies)
		m.body = append(m.body, f.Data()[:keep]...)
		c.bodies += keep
		if keep != len(f.Data()) {
			s.issues = appendUnique(s.issues, "h2-body-limit")
		}
		m.ended = f.StreamEnded()
		c.maybeEmit(s)
	case *http2.RSTStreamFrame:
		if _, closed := c.closed[f.StreamID]; closed {
			return
		}
		s := c.streams[f.StreamID]
		if s == nil {
			c.fail("h2-reset-idle-stream")
			return
		}
		s.issues = appendUnique(s.issues, fmt.Sprintf("h2-reset-%d", f.ErrCode))
		c.emit(s)
		c.closed[f.StreamID] = false
	case *http2.GoAwayFrame:
		c.issues = appendUnique(c.issues, fmt.Sprintf("h2-goaway-%d", f.ErrCode))
		for _, s := range c.streams {
			if side == 1 && s.id%2 == 1 && s.id > f.LastStreamID {
				s.issues = appendUnique(s.issues, "h2-goaway-unprocessed")
			}
		}
	}
}

func (c *h2Connection) headerFragment(side int, fragment []byte, end bool) {
	d := c.direction[side]
	d.blockBytes += len(fragment)
	if d.blockBytes > maxHTTPHeaders {
		c.fail("h2-header-block-limit")
		return
	}
	_, err := d.decoder.Write(fragment)
	if err != nil {
		c.fail("h2-invalid-hpack")
		return
	}
	if d.headerBytes > maxHTTPHeaders || !d.decoder.EmitEnabled() {
		c.fail("h2-header-list-limit")
		return
	}
	if !end {
		return
	}
	if d.decoder.Close() != nil {
		c.fail("h2-incomplete-hpack")
		return
	}
	id, messageSide := d.blockID, side
	if d.promiseID != 0 {
		id, messageSide = d.promiseID, 0
	}
	if reset, closed := c.closed[id]; closed && !reset {
		c.issues = appendUnique(c.issues, "h2-in-flight-headers-after-reset")
		d.fields, d.blockID, d.promiseID, d.blockBytes, d.headerBytes = nil, 0, 0, 0, 0
		return
	}
	s := c.stream(id)
	if s == nil {
		return
	}
	m := &s.message[messageSide]
	if m.ended {
		c.fail("h2-headers-after-end-stream")
		return
	}
	if messageSide == 0 && !m.started && id%2 == 1 {
		if id <= c.lastRequest {
			c.fail("h2-reused-request-stream")
			return
		}
		c.lastRequest = id
	}
	issues := validateH2Headers(d.fields, messageSide, m.started)
	s.issues = appendUnique(s.issues, issues...)
	c.headers += d.headerBytes
	if c.headers > h2MaxHeaders {
		c.fail("h2-retained-header-limit")
		return
	}
	if !m.started {
		// Informational responses do not finish the stream or become trailers.
		status, _ := strconv.Atoi(h2Header(d.fields, ":status"))
		if messageSide == 1 && status >= 100 && status < 200 {
			if status == 101 || d.blockEnd {
				s.issues = appendUnique(s.issues, "h2-invalid-informational-response")
			}
			m.headers, m.timestamp, m.started = d.fields, d.blockTimestamp, true
			c.write(s, false)
			m.headers, m.started = nil, false
			c.headers -= d.headerBytes
		} else {
			m.headers, m.timestamp, m.started, m.ended = d.fields, d.blockTimestamp, true, d.blockEnd
		}
	} else {
		m.trailers, m.ended = append(m.trailers, d.fields...), d.blockEnd
		if !d.blockEnd {
			s.issues = appendUnique(s.issues, "h2-trailers-without-end-stream")
		}
	}
	d.fields, d.blockID, d.promiseID, d.blockBytes, d.headerBytes = nil, 0, 0, 0, 0
	c.maybeEmit(s)
}

func h2Header(fields []*types.HTTPHeaderEvidence, name string) string {
	for _, f := range fields {
		if string(f.Name) == name {
			return string(f.Value)
		}
	}
	return ""
}

func validateH2Headers(fields []*types.HTTPHeaderEvidence, side int, trailers bool) []string {
	var issues []string
	seen := make(map[string]bool)
	regular := false
	for _, f := range fields {
		name, value := string(f.Name), string(f.Value)
		pseudo := strings.HasPrefix(name, ":")
		if name != strings.ToLower(name) || !validHeaderName(strings.TrimPrefix(name, ":")) || strings.ContainsAny(value, "\x00\r\n") {
			issues = appendUnique(issues, "h2-invalid-header")
		}
		if pseudo {
			if regular || trailers || seen[name] {
				issues = appendUnique(issues, "h2-invalid-pseudo-header")
			}
			allowed := side == 0 && (name == ":method" || name == ":scheme" || name == ":authority" || name == ":path") || side == 1 && name == ":status"
			if !allowed {
				issues = appendUnique(issues, "h2-invalid-pseudo-header")
			}
		} else {
			regular = true
		}
		if name == "connection" || name == "upgrade" || name == "keep-alive" || name == "proxy-connection" || name == "transfer-encoding" || name == "te" && value != "trailers" {
			issues = appendUnique(issues, "h2-connection-specific-header")
		}
		if name == "content-length" && seen[name] {
			issues = appendUnique(issues, "duplicate-content-length")
		}
		seen[name] = true
	}
	if !trailers {
		if side == 0 {
			method := h2Header(fields, ":method")
			if method == "" || method == "CONNECT" && (!seen[":authority"] || seen[":path"] || seen[":scheme"]) || method != "CONNECT" && (h2Header(fields, ":path") == "" || h2Header(fields, ":scheme") == "") {
				issues = appendUnique(issues, "h2-missing-request-pseudo-header")
			}
		} else {
			status := h2Header(fields, ":status")
			n, err := strconv.Atoi(status)
			if err != nil || len(status) != 3 || n < 100 || n > 599 {
				issues = appendUnique(issues, "h2-invalid-status")
			}
		}
	}
	return issues
}

func (c *h2Connection) maybeEmit(s *h2Transaction) {
	if s.message[0].ended && s.message[1].ended {
		c.emit(s)
	}
}

func h2ResponseHasNoBody(s *h2Transaction) bool {
	method := h2Header(s.message[0].headers, ":method")
	if s.upgrade != nil {
		method = s.upgrade.request.Method
	}
	status := h2Header(s.message[1].headers, ":status")
	return method == "HEAD" || status == "204" || status == "304"
}

func (c *h2Connection) emit(s *h2Transaction) {
	c.write(s, true)
	for _, m := range s.message {
		c.bodies -= len(m.body)
		for _, fields := range [][]*types.HTTPHeaderEvidence{m.headers, m.trailers} {
			for _, field := range fields {
				c.headers -= len(field.Name) + len(field.Value) + 32
			}
		}
	}
	delete(c.streams, s.id)
	c.closed[s.id] = true
}

func (c *h2Connection) finish() {
	for side, d := range c.direction {
		if d.blockID == 0 {
			continue
		}
		id, messageSide := d.blockID, side
		if d.promiseID != 0 {
			id, messageSide = d.promiseID, 0
		}
		s := c.streams[id]
		if s == nil {
			continue
		}
		m := &s.message[messageSide]
		if !m.started {
			m.headers, m.timestamp, m.started = d.fields, d.blockTimestamp, len(d.fields) > 0
		} else {
			m.trailers = append(m.trailers, d.fields...)
		}
		for _, field := range d.fields {
			c.headers += len(field.Name) + len(field.Value) + 32
		}
		s.issues = appendUnique(s.issues, "h2-incomplete-headers")
	}
	ids := make([]int, 0, len(c.streams))
	for id := range c.streams {
		ids = append(ids, int(id))
	}
	sort.Ints(ids)
	for _, id := range ids {
		c.emit(c.streams[uint32(id)])
	}
	if len(c.issues) > 0 {
		// A connection-level record also preserves failures after the last stream
		// was emitted, or before any decodable headers were observed.
		r := c.baseRecord(0)
		r.ParseQualifications = append([]string(nil), c.issues...)
		r.ReassemblyStatus = strings.Join(c.issues, ",")
		c.reader.qualifyPairing(r, false)
		writeHTTP(r, c.reader.conversation.Ident)
	}
}

func (c *h2Connection) baseRecord(id uint32) *types.HTTP {
	v := c.reader.conversation
	return &types.HTTP{Timestamp: c.firstTimestamp, Proto: "HTTP/2.0", HTTP2StreamID: id, CommunityID: v.CommunityID, Flow: v.Ident, SrcIP: v.ClientIP, DstIP: v.ServerIP, SrcPort: v.ClientPort, DstPort: v.ServerPort}
}

func h2HTTPHeaders(fields []*types.HTTPHeaderEvidence) http.Header {
	h := make(http.Header)
	for _, field := range fields {
		if !bytes.HasPrefix(field.Name, []byte(":")) {
			h.Add(string(field.Name), string(field.Value))
		}
	}
	return h
}

func (c *h2Connection) write(s *h2Transaction, final bool) {
	r := c.baseRecord(s.id)
	issues := appendUnique(append([]string(nil), s.issues...), c.issues...)
	if c.reader.initialUnknown {
		addStatus(r, "unknown-initial-stream-loss")
	}
	for side, m := range s.message {
		if final && !m.ended {
			issues = appendUnique(issues, fmt.Sprintf("h2-incomplete-direction-%d", side))
		}
		if c.direction[side].wire.initialUnknown {
			addStatus(r, "unknown-initial-stream-loss")
		}
		length := h2Header(m.headers, "content-length")
		if length != "" && m.ended {
			n, err := strconv.ParseInt(length, 10, 64)
			noBody := side == 1 && h2ResponseHasNoBody(s)
			if err != nil || n < 0 || strings.Trim(length, "0123456789") != "" || !noBody && n != m.length {
				issues = appendUnique(issues, "h2-content-length-mismatch")
			}
		}
	}
	request, response := &s.message[0], &s.message[1]
	if response.started {
		status, _ := strconv.Atoi(h2Header(response.headers, ":status"))
		res := &http.Response{Proto: "HTTP/2.0", StatusCode: status, Header: h2HTTPHeaders(response.headers), ContentLength: response.length, Body: io.NopCloser(bytes.NewReader(response.body))}
		responseRecord := newHTTPFromResponse(res)
		responseRecord.Proto, responseRecord.HTTP2StreamID, responseRecord.CommunityID, responseRecord.Flow = r.Proto, r.HTTP2StreamID, r.CommunityID, r.Flow
		responseRecord.SrcIP, responseRecord.DstIP, responseRecord.SrcPort, responseRecord.DstPort = r.DstIP, r.SrcIP, r.DstPort, r.SrcPort
		responseRecord.ReassemblyStatus, responseRecord.Timestamp = r.ReassemblyStatus, response.timestamp
		r = responseRecord
		atomic.AddInt64(&streamutils.Stats.NumResponses, 1)
	}
	if request.started {
		req := s.upgrade
		if req == nil {
			target := h2Header(request.headers, ":path")
			u, err := url.ParseRequestURI(target)
			if h2Header(request.headers, ":method") == "CONNECT" {
				target = h2Header(request.headers, ":authority")
				u, err = &url.URL{Host: target}, nil
			}
			if err != nil {
				u = &url.URL{Path: target}
				issues = appendUnique(issues, "h2-invalid-request-target")
			}
			httpReq := &http.Request{Proto: "HTTP/2.0", ProtoMajor: 2, Method: h2Header(request.headers, ":method"), Host: h2Header(request.headers, ":authority"), URL: u, RequestURI: target, Header: h2HTTPHeaders(request.headers), ContentLength: request.length, Body: io.NopCloser(bytes.NewReader(request.body))}
			if httpReq.Host == "" {
				httpReq.Host = httpReq.Header.Get("Host")
			}
			_ = parseEvidenceForm(httpReq, request.body)
			v := c.reader.conversation
			req = &httpRequest{request: httpReq, timestamp: request.timestamp, clientIP: v.ClientIP, serverIP: v.ServerIP, clientPort: v.ClientPort, serverPort: v.ServerPort, flow: v.Ident}
		}
		setRequest(r, req)
		r.Proto = "HTTP/2.0"
		atomic.AddInt64(&streamutils.Stats.NumRequests, 1)
	}
	if s.upgrade == nil {
		r.RequestHeaders = request.headers
	}
	r.ResponseHeaders, r.RequestTrailers, r.ResponseTrailers = response.headers, request.trailers, response.trailers
	r.ParseQualifications = appendUnique(r.ParseQualifications, issues...)
	for _, issue := range issues {
		addStatus(r, issue)
	}
	c.reader.qualifyPairing(r, request.started && response.started)
	writeHTTP(r, c.reader.conversation.Ident)
	if c.reader.transportObservation == "" && final && len(issues) == 0 && decoderconfig.Instance.FileStorage != "" {
		for side, m := range s.message {
			if !m.started || !m.ended || len(m.body) == 0 {
				continue
			}
			metadata := file.FileMetadata{Timestamp: m.timestamp, ConnectionUID: r.Flow, HTTPMethod: r.Method, HTTPURL: r.URL, Host: r.Host}
			if side == 0 {
				metadata.FlowDirection, metadata.ContentType = "client_to_server", r.ContentType
			} else {
				metadata.FlowDirection, metadata.ContentType, metadata.HTTPStatusCode = "server_to_client", r.ResContentType, int(r.StatusCode)
			}
			metadata.Encoding = h2HTTPHeaders(m.headers).Values("Content-Encoding")
			file.RecordExtractionIssue((&HTTPFileExtractor{}).ExtractFile(c.reader.conversation, m.body, metadata))
		}
	}
}
