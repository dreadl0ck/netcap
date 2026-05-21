/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package mcp

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestStreamAuditRecordsDecodesSSE drives the SSE parser against a
// canned event stream: 2 record events, a progress event (ignored by
// the parser since we don't surface it), and a terminal complete event.
func TestStreamAuditRecordsDecodesSSE(t *testing.T) {
	const body = "event: record\ndata: {\"x\":1}\n\n" +
		"event: record\ndata: {\"x\":2}\n\n" +
		"event: progress\ndata: {\"count\":2,\"scanned\":2}\n\n" +
		"event: complete\ndata: {\"total\":2,\"scanned\":2,\"executionTimeMs\":3}\n\n"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/stream") {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, body)
	}))
	defer ts.Close()

	c := NewNetcapClient(ts.URL)
	recs, comp, term, err := c.StreamAuditRecords("DNS", nil, 1<<20)
	if err != nil {
		t.Fatalf("StreamAuditRecords: %v", err)
	}
	if term != "complete" {
		t.Errorf("terminal = %q, want \"complete\"", term)
	}
	if len(recs) != 2 {
		t.Fatalf("records = %d, want 2", len(recs))
	}
	if string(recs[0]) != `{"x":1}` || string(recs[1]) != `{"x":2}` {
		t.Errorf("record payloads: %q %q", recs[0], recs[1])
	}
	if !strings.Contains(string(comp), `"total":2`) {
		t.Errorf("complete payload = %s", comp)
	}
}

// TestStreamAuditRecordsHandlesErrorEvent: when the server sends an
// `event: error`, the parser captures it as terminal="error".
func TestStreamAuditRecordsHandlesErrorEvent(t *testing.T) {
	const body = "event: error\ndata: {\"error\":\"file not found\"}\n\n"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, body)
	}))
	defer ts.Close()

	c := NewNetcapClient(ts.URL)
	recs, comp, term, err := c.StreamAuditRecords("DNS", nil, 1<<20)
	if err != nil {
		t.Fatalf("StreamAuditRecords: %v", err)
	}
	if len(recs) != 0 {
		t.Errorf("records = %d, want 0", len(recs))
	}
	if term != "error" {
		t.Errorf("terminal = %q, want \"error\"", term)
	}
	if !strings.Contains(string(comp), "file not found") {
		t.Errorf("error payload = %s", comp)
	}
}

// TestStreamAuditRecordsHTTPError surfaces 4xx/5xx as Go errors.
func TestStreamAuditRecordsHTTPError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no such audit type", http.StatusNotFound)
	}))
	defer ts.Close()

	c := NewNetcapClient(ts.URL)
	_, _, _, err := c.StreamAuditRecords("DNS", nil, 1<<20)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("error doesn't mention status: %v", err)
	}
}

// TestValidAuditTypeName guards against URL-path injection through the
// type argument.
func TestValidAuditTypeName(t *testing.T) {
	good := []string{"DNS", "HTTP", "Connection", "Modbus", "S7Comm", "Dot11", "ICMPv6", "IPv4", "EAPOL"}
	bad := []string{"", "../etc/passwd", "DNS/values", "DNS stream", "DNS.gz", "ProtocolWithSpaces ", strings.Repeat("A", 65)}
	for _, s := range good {
		if !validAuditTypeName(s) {
			t.Errorf("validAuditTypeName(%q) = false, want true", s)
		}
	}
	for _, s := range bad {
		if validAuditTypeName(s) {
			t.Errorf("validAuditTypeName(%q) = true, want false", s)
		}
	}
}
