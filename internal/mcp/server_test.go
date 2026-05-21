/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package mcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestAdminAuthRejectsMissingToken verifies that with an admin token
// configured, requests without an Authorization header are rejected
// with 401 and the right WWW-Authenticate challenge.
func TestAdminAuthRejectsMissingToken(t *testing.T) {
	srv, err := New(Options{BaseURL: "http://127.0.0.1:1", AdminToken: "s3cret"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ts := httptest.NewServer(srv.HTTPHandler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/mcp", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
	if !strings.Contains(resp.Header.Get("WWW-Authenticate"), "Bearer realm=") {
		t.Fatalf("missing WWW-Authenticate challenge: %q", resp.Header.Get("WWW-Authenticate"))
	}
}

// TestAdminAuthRejectsWrongToken verifies the constant-time comparison
// rejects a token that's the wrong value (even if same length).
func TestAdminAuthRejectsWrongToken(t *testing.T) {
	srv, err := New(Options{BaseURL: "http://127.0.0.1:1", AdminToken: "abcdef"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ts := httptest.NewServer(srv.HTTPHandler())
	defer ts.Close()

	req, _ := http.NewRequest("POST", ts.URL+"/mcp", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer XXXXXX")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for wrong token, got %d", resp.StatusCode)
	}
}

// TestAdminAuthDisabledWhenNoToken verifies the safety net: even if /mcp
// is mounted, an empty admin token produces 503 (never accidentally
// open-served).
func TestAdminAuthDisabledWhenNoToken(t *testing.T) {
	srv, err := New(Options{BaseURL: "http://127.0.0.1:1", AdminToken: ""})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ts := httptest.NewServer(srv.HTTPHandler())
	defer ts.Close()

	req, _ := http.NewRequest("POST", ts.URL+"/mcp", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer anything")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 with empty token, got %d", resp.StatusCode)
	}
}

// TestToolNameValidation enforces Anthropic's tool-name regex at
// registration time. This catches a class of bugs the reaper project
// hit in production (dotted/colon-separated names broke Claude clients).
func TestToolNameValidation(t *testing.T) {
	cases := []struct {
		name string
		ok   bool
	}{
		{"list_hosts", true},
		{"a", true},
		{"ABC_123-xyz", true},
		{"", false},
		{"has.dot", false},
		{"has space", false},
		{"has:colon", false},
		{"has/slash", false},
		{strings.Repeat("a", 64), true},
		{strings.Repeat("a", 65), false},
	}
	for _, c := range cases {
		if got := validToolName(c.name); got != c.ok {
			t.Errorf("validToolName(%q)=%v, want %v", c.name, got, c.ok)
		}
	}
}

// TestNewRequiresBaseURL ensures we don't construct a Server with a
// missing baseURL (which would silently produce broken tools).
func TestNewRequiresBaseURL(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Fatal("expected error for empty BaseURL")
	}
}

// TestTokenFingerprintEmptyWhenUnset documents that no log line should
// leak an empty-token fingerprint.
func TestTokenFingerprintEmptyWhenUnset(t *testing.T) {
	srv, err := New(Options{BaseURL: "http://127.0.0.1:1"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := srv.TokenFingerprint(); got != "" {
		t.Errorf("TokenFingerprint() with no token = %q, want \"\"", got)
	}
}

// TestAllowDenyLists verifies that the registration filter excludes
// tools according to AllowedTools / DisallowedTools.
func TestAllowDenyLists(t *testing.T) {
	srv, err := New(Options{
		BaseURL:         "http://127.0.0.1:1",
		AllowedTools:    []string{"list_hosts", "list_decoders"},
		DisallowedTools: []string{"list_hosts"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Allowed minus denied = {list_decoders}.
	if got := srv.mcpSrv.GetTool("list_hosts"); got != nil {
		t.Error("list_hosts should be denied")
	}
	if got := srv.mcpSrv.GetTool("list_decoders"); got == nil {
		t.Error("list_decoders should be allowed")
	}
	if got := srv.mcpSrv.GetTool("ingest_pcap"); got != nil {
		t.Error("ingest_pcap should be filtered out (not on allow list)")
	}
}
