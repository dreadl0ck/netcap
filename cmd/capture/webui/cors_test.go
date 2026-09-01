/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package webui

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func corsProbe(t *testing.T, s *Server, origin string) http.Header {
	t.Helper()

	h := s.corsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	r := httptest.NewRequest("GET", "/api/status", nil)
	if origin != "" {
		r.Header.Set("Origin", origin)
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	return rec.Result().Header
}

// In service mode the API is public and unauthenticated and serves data
// extracted from uploaded captures, so "Access-Control-Allow-Origin: *" let any
// website read it. The web UI never needs CORS: one server serves the SPA and
// the API.
func TestCORSServiceModeIsSameOriginByDefault(t *testing.T) {
	t.Setenv("NC_CORS_ALLOWED_ORIGINS", "")

	s := &Server{isServiceMode: true}

	for _, origin := range []string{"", "https://evil.example", "https://try.netcap.io"} {
		got := corsProbe(t, s, origin).Get("Access-Control-Allow-Origin")
		if got != "" {
			t.Errorf("origin %q: got ACAO %q, want none", origin, got)
		}
	}
}

// Local mode is a single-user tool on the operator's own machine; permissive
// CORS there costs nothing and keeps cross-origin dev setups working.
func TestCORSLocalModeStaysPermissive(t *testing.T) {
	s := &Server{isServiceMode: false}

	if got := corsProbe(t, s, "http://localhost:5173").Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("local mode: got ACAO %q, want *", got)
	}
}

func TestCORSServiceModeHonoursConfiguredOrigins(t *testing.T) {
	t.Setenv("NC_CORS_ALLOWED_ORIGINS", "https://ui.example, https://other.example")

	s := &Server{isServiceMode: true}

	// Allowed origin is echoed back specifically, never as "*".
	h := corsProbe(t, s, "https://ui.example")
	if got := h.Get("Access-Control-Allow-Origin"); got != "https://ui.example" {
		t.Errorf("allowed origin: got %q", got)
	}

	// Vary: Origin must be present or a cache could hand one origin's response
	// to another.
	if h.Get("Vary") != "Origin" {
		t.Errorf("expected Vary: Origin, got %q", h.Get("Vary"))
	}

	// Anything not listed gets nothing.
	if got := corsProbe(t, s, "https://evil.example").Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("unlisted origin: got ACAO %q, want none", got)
	}
}
