/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
)

// SSERecord is one decoded event from the audit-record stream endpoint.
type SSERecord struct {
	Event string          // "record", "progress", "complete", "error"
	Data  json.RawMessage // event payload (verbatim JSON)
}

// StreamAuditRecords consumes /api/audit/<auditType>/stream as Server-Sent
// Events and returns the slice of "record" events plus the terminal
// "complete" payload. It rejects records beyond the requested limit and
// reads up to maxBytes from the wire.
//
// Server SSE event semantics:
//
//	event: record    -> data is one JSON-encoded audit record
//	event: progress  -> data is {count, scanned}
//	event: complete  -> data is {total, scanned, executionTimeMs}
//	event: error     -> data is {error}
//
// Returns:
//   - records: the per-record JSON payloads
//   - completeJSON: the JSON object from the final "complete" event (or
//     "error" payload if that came first)
//   - terminalEvent: "complete" or "error"
//   - err: transport or parse error (not an SSE "event: error" — that's
//     surfaced in terminalEvent)
func (c *NetcapClient) StreamAuditRecords(auditType string, q url.Values, maxBytes int) (records []json.RawMessage, completeJSON json.RawMessage, terminalEvent string, err error) {
	return c.streamAuditRecords(context.Background(), auditType, q, maxBytes)
}

func (c *NetcapClient) streamAuditRecords(ctx context.Context, auditType string, q url.Values, maxBytes int) (records []json.RawMessage, completeJSON json.RawMessage, terminalEvent string, err error) {
	records = make([]json.RawMessage, 0)
	u := c.baseURL + "/api/audit/" + url.PathEscape(auditType) + "/stream"
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, nil, "", err
	}
	// The webui's gzip middleware bypasses compression for SSE. Setting
	// Accept explicitly avoids any ambiguity.
	req.Header.Set("Accept", "text/event-stream")
	c.authorizeBackend(req)

	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, nil, "", fmt.Errorf("GET %s: %w", req.URL.Path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, nil, "", backendDiagnostic(req, resp)
	}

	// Bound the total bytes we'll buffer so a runaway server can't OOM us.
	if maxBytes <= 0 {
		maxBytes = 8 << 20 // 8 MiB
	}
	limited := io.LimitReader(resp.Body, int64(maxBytes))
	recordLimit, _ := strconv.Atoi(q.Get("limit"))
	countOnly := q.Get("countOnly") == "true"

	// SSE events are separated by blank lines; each event is one or more
	// header lines ("event: name", "data: payload") followed by \n\n.
	scanner := bufio.NewScanner(limited)
	scanner.Buffer(make([]byte, 0, min(maxBytes, 64<<10)), (16<<20)+1024)
	scanner.Split(scanAuditEventLine)

	var (
		curEvent string
		curData  []byte
	)
	flush := func() error {
		if curEvent == "" && len(curData) == 0 {
			return nil
		}
		payload := json.RawMessage(bytes.TrimSpace(curData))
		switch curEvent {
		case "record":
			if countOnly || recordLimit > 0 && len(records) >= recordLimit {
				return fmt.Errorf("SSE record count exceeds requested page bounds")
			}
			if len(payload) == 0 || payload[0] != '{' || !json.Valid(payload) {
				return fmt.Errorf("invalid SSE record payload")
			}
			records = append(records, payload)
		case "complete":
			completeJSON = payload
			terminalEvent = "complete"
		case "error":
			completeJSON = payload
			terminalEvent = "error"
		}
		curEvent = ""
		curData = nil
		return nil
	}
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			if err := flush(); err != nil {
				return nil, nil, "", err
			}
			if terminalEvent != "" {
				if len(completeJSON) == 0 || completeJSON[0] != '{' || !json.Valid(completeJSON) {
					return nil, nil, "", fmt.Errorf("invalid SSE terminal payload")
				}
				if terminalEvent == "complete" {
					if err := validateAuditCompletion(completeJSON, q, len(records)); err != nil {
						return nil, nil, "", err
					}
				}
				return records, completeJSON, terminalEvent, nil
			}
			continue
		}
		if name, ok := bytes.CutPrefix(line, []byte("event:")); ok {
			curEvent = string(bytes.TrimSpace(name))
		} else if data, ok := bytes.CutPrefix(line, []byte("data:")); ok {
			if len(curData) > 0 {
				curData = append(curData, '\n')
			}
			curData = append(curData, data...)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, "", fmt.Errorf("reading SSE: %w", err)
	}
	if terminalEvent == "" {
		// No "complete" event arrived (truncated stream or server bug).
		terminalEvent = "incomplete"
	}
	return records, completeJSON, terminalEvent, nil
}

// A bare CR at EOF must not become the blank line that commits an event.
func scanAuditEventLine(data []byte, _ bool) (int, []byte, error) {
	if i := bytes.IndexByte(data, '\n'); i >= 0 {
		return i + 1, bytes.TrimSuffix(data[:i], []byte("\r")), nil
	}
	return 0, nil, nil
}

func validateAuditCompletion(payload json.RawMessage, query url.Values, count int) error {
	var summary struct {
		Count      json.RawMessage `json:"count"`
		NextOffset json.RawMessage `json:"nextOffset"`
		Total      json.RawMessage `json:"total"`
		HasMore    json.RawMessage `json:"hasMore"`
	}
	if err := json.Unmarshal(payload, &summary); err != nil {
		return fmt.Errorf("invalid SSE completion summary: %w", err)
	}
	if summary.Count != nil {
		got, err := strconv.Atoi(string(summary.Count))
		if err != nil || got != count {
			return fmt.Errorf("SSE completion count does not match delivered records")
		}
	}
	offset := 0
	if raw := query.Get("offset"); raw != "" {
		var err error
		offset, err = strconv.Atoi(raw)
		if err != nil || offset < 0 {
			return fmt.Errorf("invalid requested SSE offset")
		}
	}
	if summary.NextOffset != nil {
		got, parseErr := strconv.Atoi(string(summary.NextOffset))
		if parseErr != nil || got < offset || got-offset != count {
			return fmt.Errorf("SSE completion nextOffset does not match delivered records")
		}
	}
	countOnly := query.Get("countOnly") == "true"
	total := 0
	if summary.Total != nil {
		var err error
		total, err = strconv.Atoi(string(summary.Total))
		if err != nil || total < 0 || count > 0 && (offset > total || count > total-offset) {
			return fmt.Errorf("SSE completion total conflicts with delivered records")
		}
	}
	if summary.HasMore != nil {
		switch string(summary.HasMore) {
		case "true":
			if countOnly || count == 0 || summary.Total != nil && count >= total-offset {
				return fmt.Errorf("SSE completion hasMore has no valid continuation")
			}
		case "false":
			if !countOnly && summary.Total != nil && offset < total && count < total-offset {
				return fmt.Errorf("SSE completion hides remaining records")
			}
		default:
			return fmt.Errorf("invalid SSE completion hasMore")
		}
	}
	return nil
}
