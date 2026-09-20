package mcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestGetAs(t *testing.T) {
	type response struct {
		Name  string `json:"name"`
		Count int    `json:"count"`
	}
	for _, tt := range []struct {
		name        string
		body        string
		status      int
		want        response
		decodeError bool
	}{
		{name: "success", body: `{"name":"netcap","count":2}`, status: 200, want: response{"netcap", 2}},
		{name: "zero", body: `{}`, status: 200},
		{name: "null", body: `null`, status: 200},
		{name: "malformed", body: `{"name":`, status: 200, decodeError: true},
		{name: "partial decode", body: `{"name":"discard","count":"bad"}`, status: 200, decodeError: true},
		{name: "empty", status: 204, decodeError: true},
		{name: "http error", body: `upstream failed`, status: 500},
		{name: "redirect status policy", body: `{"count":3}`, status: 302, want: response{Count: 3}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			query := url.Values{"inputFile": {"a b&c.pcap"}, "tag": {"one", "two"}}
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/api/test" || r.URL.RawQuery != query.Encode() || r.Header.Get("Accept") != "application/json" {
					t.Errorf("unexpected request: %s %s %v", r.Method, r.URL, r.Header)
				}
				w.WriteHeader(tt.status)
				fmt.Fprint(w, tt.body)
			}))
			defer ts.Close()
			client := NewNetcapClient(ts.URL)
			got, err := client.GetAs[response]("/api/test", query)
			if got != tt.want {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
			if tt.decodeError {
				var syntax *json.SyntaxError
				var mismatch *json.UnmarshalTypeError
				if err == nil || !strings.Contains(err.Error(), "decoding GET /api/test response:") || (!errors.As(err, &syntax) && !errors.As(err, &mismatch)) {
					t.Fatalf("expected wrapped JSON error, got %v", err)
				}
			} else if (err != nil) != (tt.status >= 400) {
				t.Fatalf("unexpected error: %v", err)
			}
			raw, rawErr := client.Get("/api/test", query)
			if tt.status >= 400 {
				if raw != nil || rawErr == nil || err == nil || err.Error() != rawErr.Error() {
					t.Fatalf("HTTP error differs from Get: %q, %v, %v", raw, rawErr, err)
				}
			} else if rawErr != nil || string(raw) != tt.body {
				t.Fatalf("Get changed raw response: %q, %v", raw, rawErr)
			}
		})
	}
}

func TestGetAsNil(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "null")
	}))
	defer ts.Close()
	c := NewNetcapClient(ts.URL)
	if got, err := c.GetAs[map[string]any]("/", nil); got != nil || err != nil {
		t.Fatalf("null map: %v, %v", got, err)
	}
	if got, err := c.GetAs[[]string]("/", nil); got != nil || err != nil {
		t.Fatalf("null slice: %v, %v", got, err)
	}
	if got, err := c.GetAs[*int]("/", nil); got != nil || err != nil {
		t.Fatalf("null pointer: %v, %v", got, err)
	}
}

type failingTransport struct{ err error }

func (f failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, f.err
}

func TestGetAsTransportError(t *testing.T) {
	want := errors.New("transport failed")
	c := NewNetcapClient("http://netcap.invalid")
	c.hc.Transport = failingTransport{want}
	got, err := c.GetAs[*int]("/api/test", nil)
	if got != nil || !errors.Is(err, want) {
		t.Fatalf("got %v, %v; want nil and wrapped transport error", got, err)
	}
	raw, rawErr := c.Get("/api/test", nil)
	if raw != nil || !errors.Is(rawErr, want) || rawErr.Error() != err.Error() {
		t.Fatalf("transport error differs from Get: %q, %v", raw, rawErr)
	}
}
