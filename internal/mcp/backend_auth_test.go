package mcp

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
