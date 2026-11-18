package mcp

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/iotest"
)

type rawTestTransport func(*http.Request) (*http.Response, error)

func (f rawTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type unreadRawBody struct {
	t      *testing.T
	closed bool
}

func (b *unreadRawBody) Read([]byte) (int, error) {
	b.t.Error("oversized response body was read")
	return 0, io.EOF
}

func (b *unreadRawBody) Close() error { b.closed = true; return nil }

func TestRawDownloadRejectsOversizedLengthBeforeReading(t *testing.T) {
	body := &unreadRawBody{t: t}
	c := &NetcapClient{baseURL: "http://fixture.test", hc: &http.Client{Transport: rawTestTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, ContentLength: (16 << 20) + 1, Body: body}, nil
	})}}
	data, _, err := c.GetRawContext(t.Context(), "/api/fixture", nil)
	if err == nil || !strings.Contains(err.Error(), "backend response exceeds") || data != nil || !body.closed {
		t.Fatalf("data=%q, err=%v, closed=%t", data, err, body.closed)
	}
}

func TestRawDownloadPreservesStatusWithBoundedDiagnostic(t *testing.T) {
	diagnostic := strings.NewReader(strings.Repeat("x", 4096))
	c := &NetcapClient{baseURL: "http://fixture.test", hc: &http.Client{Transport: rawTestTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusServiceUnavailable, Status: "503 Service Unavailable", ContentLength: 16<<20 + 1, Body: io.NopCloser(diagnostic)}, nil
	})}}
	data, _, err := c.GetRawContext(t.Context(), "/api/fixture", nil)
	var backend *BackendError
	if data != nil || !errors.As(err, &backend) || backend.StatusCode != 503 || !strings.HasSuffix(err.Error(), "...[truncated]") {
		t.Fatalf("unexpected download result: bytes=%d err=%v", len(data), err)
	}
	if read := 4096 - diagnostic.Len(); read != 501 {
		t.Fatalf("diagnostic read %d bytes, want 501", read)
	}
}

func TestRawDownloadPreservesStatusWhenDiagnosticReadFails(t *testing.T) {
	c := &NetcapClient{baseURL: "http://fixture.test", hc: &http.Client{Transport: rawTestTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusBadGateway, Body: io.NopCloser(iotest.ErrReader(io.ErrUnexpectedEOF))}, nil
	})}}
	_, _, err := c.GetRawContext(t.Context(), "/api/fixture", nil)
	var backend *BackendError
	if !errors.As(err, &backend) || backend.StatusCode != 502 || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("status or read error lost: %v", err)
	}
}

func TestJSONBackendFailurePreservesStatusWhenBodyCannotBeRead(t *testing.T) {
	for _, oversized := range []bool{false, true} {
		var length int64 = -1
		unread := &unreadRawBody{t: t}
		body := io.NopCloser(iotest.ErrReader(io.ErrUnexpectedEOF))
		if oversized {
			length, body = maxBackendResponseBytes+1, unread
		}
		c := &NetcapClient{baseURL: "http://fixture.test", hc: &http.Client{Transport: rawTestTransport(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusBadGateway, ContentLength: length, Body: body}, nil
		})}}
		data, err := c.Get("/api/fixture", nil)
		var backend *BackendError
		if data != nil || !errors.As(err, &backend) || backend.StatusCode != http.StatusBadGateway || len(backend.Body) != 0 {
			t.Fatalf("oversized=%t: unexpected response: %s, %v", oversized, data, err)
		}
		if oversized && (!unread.closed || !strings.Contains(err.Error(), "backend response exceeds")) {
			t.Fatalf("oversized body was not rejected and closed: %v", err)
		}
		if !oversized && !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("read error lost: %v", err)
		}
	}
}

func TestJSONBackendErrorReadScope(t *testing.T) {
	for _, path := range []string{"/api/fixture", "/api/mcp/operator/delivery"} {
		t.Run(path, func(t *testing.T) {
			payload := `{"report":{"detail":"` + strings.Repeat("x", 4096) + `"},"code":"fixture"}`
			body := strings.NewReader(payload)
			c := &NetcapClient{baseURL: "http://fixture.test", hc: &http.Client{Transport: rawTestTransport(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusConflict, ContentLength: -1, Body: io.NopCloser(body)}, nil
			})}}
			_, err := c.PostJSONContext(t.Context(), path, nil)
			var backend *BackendError
			if !errors.As(err, &backend) || backend.StatusCode != http.StatusConflict {
				t.Fatalf("lost conflict status: %v", err)
			}
			if path == "/api/fixture" {
				if read := len(payload) - body.Len(); read != 501 || !strings.Contains(err.Error(), "...[truncated]") {
					t.Fatalf("ordinary error read %d bytes, want 501: %v", read, err)
				}
			} else if string(backend.Body) != payload {
				t.Fatal("structured operator error report was truncated")
			}
		})
	}
}

func TestBackendAdminAuthIsScopedAndDoesNotFollowRedirects(t *testing.T) {
	forwarded := false
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { forwarded = true }))
	defer foreign.Close()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/redirect" {
			http.Redirect(w, r, foreign.URL, 302)
			return
		}
		want := ""
		if r.URL.Path == "/api/owned" {
			want = "Bearer synthetic-admin"
		}
		if r.Header.Get("Authorization") != want {
			t.Errorf("%s: unexpected auth header", r.URL.Path)
		}
		w.Write([]byte(`{}`))
	}))
	defer backend.Close()
	s := &Server{baseURL: backend.URL, adminToken: "synthetic-admin"}
	c := s.newClient()
	if _, err := c.Get("/api/owned", nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.GetRaw("/api/owned", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get("/unrelated", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get("/api/redirect", nil); err == nil {
		t.Fatal("redirect became successful API data")
	}
	if forwarded {
		t.Fatal("backend credentials followed redirect")
	}
}
