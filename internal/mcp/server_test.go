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

// TestAdminAuthRejectsMissingToken pins the security-critical 401 +
// WWW-Authenticate posture for /mcp when no Authorization header is set.
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

// TestAdminAuthRejectsWrongToken: a Bearer header with a wrong (but
// same-length) token must still 401. Documents the constant-time
// comparison contract.
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

// TestAdminAuthDisabledWhenNoToken is the safety net: even if /mcp is
// mounted, an empty admin token must produce 503 — never accidentally
// serve unauthenticated traffic.
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
// registration time. Documented bug class: dotted/colon-separated
// names break Claude clients (Reaper hit this in production).
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
