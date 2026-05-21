/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// SSERecord is one decoded event from the audit-record stream endpoint.
type SSERecord struct {
	Event string          // "record", "progress", "complete", "error"
	Data  json.RawMessage // event payload (verbatim JSON)
}

// StreamAuditRecords consumes /api/audit/<auditType>/stream as Server-Sent
// Events and returns the slice of "record" events plus the terminal
// "complete" payload. Stops at limit + 1 record events (server-side limit
// is also enforced) and reads up to maxBytes from the wire to bound
// memory in case the server misbehaves.
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
	u := c.baseURL + "/api/audit/" + url.PathEscape(auditType) + "/stream"
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, nil, "", err
	}
	// The webui's gzip middleware bypasses compression for SSE. Setting
	// Accept explicitly avoids any ambiguity.
	req.Header.Set("Accept", "text/event-stream")

	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, nil, "", fmt.Errorf("GET %s: %w", req.URL.Path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, nil, "", fmt.Errorf("GET %s: %s: %s",
			req.URL.Path, resp.Status, truncate(string(body), 500))
	}

	// Bound the total bytes we'll buffer so a runaway server can't OOM us.
	if maxBytes <= 0 {
		maxBytes = 8 << 20 // 8 MiB
	}
	limited := io.LimitReader(resp.Body, int64(maxBytes))

	// SSE events are separated by blank lines; each event is one or more
	// header lines ("event: name", "data: payload") followed by \n\n.
	scanner := bufio.NewScanner(limited)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	var (
		curEvent string
		curData  strings.Builder
	)
	flush := func() {
		if curEvent == "" && curData.Len() == 0 {
			return
		}
		payload := json.RawMessage(strings.TrimSpace(curData.String()))
		switch curEvent {
		case "record":
			records = append(records, payload)
		case "complete":
			completeJSON = payload
			terminalEvent = "complete"
		case "error":
			completeJSON = payload
			terminalEvent = "error"
		}
		curEvent = ""
		curData.Reset()
	}
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			flush()
			continue
		}
		switch {
		case strings.HasPrefix(line, "event:"):
			curEvent = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		case strings.HasPrefix(line, "data:"):
			if curData.Len() > 0 {
				curData.WriteByte('\n')
			}
			curData.WriteString(strings.TrimPrefix(line, "data:"))
		case strings.HasPrefix(line, ":"):
			// SSE comment, ignored.
		}
	}
	flush()

	if err := scanner.Err(); err != nil {
		return nil, nil, "", fmt.Errorf("reading SSE: %w", err)
	}
	if terminalEvent == "" {
		// No "complete" event arrived (truncated stream or server bug).
		terminalEvent = "incomplete"
	}
	return records, completeJSON, terminalEvent, nil
}
