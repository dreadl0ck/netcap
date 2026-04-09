/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package ja4

import (
	"strings"
	"testing"
)

func TestComputeJA4H(t *testing.T) {
	tests := []struct {
		name     string
		data     *HTTPData
		wantA    string // JA4H_a part (first 8 chars)
		validate bool
	}{
		{
			name: "Chrome GET request",
			data: &HTTPData{
				Method:  "GET",
				Version: "HTTP/1.1",
				HeaderOrder: []string{
					"Host",
					"Connection",
					"Cache-Control",
					"User-Agent",
					"Accept",
					"Accept-Encoding",
					"Accept-Language",
					"Cookie",
				},
				HasCookie:      true,
				CookieFields:   []string{"session_id", "user_pref"},
				AcceptLanguage: "en-US,en;q=0.9",
			},
			wantA:    "ge11c07", // ge=GET, 11=HTTP/1.1, c=cookie present, 07=7 headers (excluding Cookie)
			validate: true,
		},
		{
			name: "POST request without cookie",
			data: &HTTPData{
				Method:  "POST",
				Version: "HTTP/1.1",
				HeaderOrder: []string{
					"Host",
					"Content-Type",
					"Content-Length",
					"User-Agent",
					"Accept",
				},
				HasCookie:      false,
				CookieFields:   nil,
				AcceptLanguage: "de-DE,de;q=0.8",
			},
			wantA:    "po11n05",
			validate: true,
		},
		{
			name: "HTTP/2 request",
			data: &HTTPData{
				Method:  "GET",
				Version: "HTTP/2",
				HeaderOrder: []string{
					":method",
					":path",
					":scheme",
					":authority",
					"user-agent",
					"accept",
				},
				HasCookie:      false,
				CookieFields:   nil,
				AcceptLanguage: "",
			},
			wantA:    "ge20n06",
			validate: true,
		},
		{
			name: "Request with Referer (should be excluded from count)",
			data: &HTTPData{
				Method:  "GET",
				Version: "HTTP/1.1",
				HeaderOrder: []string{
					"Host",
					"Referer",
					"Cookie",
					"User-Agent",
				},
				HasCookie:      true,
				CookieFields:   []string{"sid"},
				AcceptLanguage: "en-US",
			},
			wantA:    "ge11c02", // Only Host and User-Agent counted (Referer and Cookie excluded)
			validate: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ja4h := ComputeJA4H(tt.data)
			t.Logf("JA4H = %s", ja4h)

		// Check the first part matches expectations
		if !strings.HasPrefix(ja4h, tt.wantA) {
			t.Errorf("JA4H_a mismatch: want prefix %q, got %q", tt.wantA, ja4h[:7])
		}

			// Validate format
			if tt.validate && !ValidateJA4H(ja4h) {
				t.Errorf("JA4H validation failed for: %s", ja4h)
			}
		})
	}
}

func TestExtractHeaderOrder(t *testing.T) {
	tests := []struct {
		name               string
		rawRequest         string
		wantHeaderCount    int
		wantCookieFields   []string
		wantAcceptLanguage string
	}{
		{
			name: "Simple GET request",
			rawRequest: "GET / HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"User-Agent: Mozilla/5.0\r\n" +
				"Accept: text/html\r\n" +
				"Accept-Language: en-US,en;q=0.9\r\n" +
				"\r\n",
			wantHeaderCount:    4,
			wantCookieFields:   nil,
			wantAcceptLanguage: "en-US,en;q=0.9",
		},
		{
			name: "Request with cookies",
			rawRequest: "GET /page HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"Cookie: session=abc123; user=john; token=xyz\r\n" +
				"Accept-Language: de-DE\r\n" +
				"\r\n",
			wantHeaderCount:    3,
			wantCookieFields:   []string{"session", "user", "token"},
			wantAcceptLanguage: "de-DE",
		},
		{
			name: "POST request with body",
			rawRequest: "POST /api/login HTTP/1.1\r\n" +
				"Host: api.example.com\r\n" +
				"Content-Type: application/json\r\n" +
				"Content-Length: 42\r\n" +
				"Cookie: csrf=token123\r\n" +
				"\r\n" +
				`{"username":"admin","password":"secret"}`,
			wantHeaderCount:    4,
			wantCookieFields:   []string{"csrf"},
			wantAcceptLanguage: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers, cookies, acceptLang := ExtractHeaderOrder([]byte(tt.rawRequest))

			if len(headers) != tt.wantHeaderCount {
				t.Errorf("Header count mismatch: want %d, got %d (headers: %v)", tt.wantHeaderCount, len(headers), headers)
			}

			if !equalStringSlices(cookies, tt.wantCookieFields) {
				t.Errorf("Cookie fields mismatch: want %v, got %v", tt.wantCookieFields, cookies)
			}

			if acceptLang != tt.wantAcceptLanguage {
				t.Errorf("Accept-Language mismatch: want %q, got %q", tt.wantAcceptLanguage, acceptLang)
			}
		})
	}
}

func TestExtractHTTPDataFromRaw(t *testing.T) {
	rawRequest := "GET /test HTTP/1.1\r\n" +
		"Host: www.example.com\r\n" +
		"Connection: keep-alive\r\n" +
		"User-Agent: TestClient/1.0\r\n" +
		"Accept: */*\r\n" +
		"Accept-Language: en-US,en;q=0.5\r\n" +
		"Cookie: session=sess123; pref=dark\r\n" +
		"Referer: https://www.example.com/\r\n" +
		"\r\n"

	data := ExtractHTTPDataFromRaw([]byte(rawRequest))

	if data.Method != "GET" {
		t.Errorf("Method mismatch: want GET, got %s", data.Method)
	}

	if data.Version != "HTTP/1.1" {
		t.Errorf("Version mismatch: want HTTP/1.1, got %s", data.Version)
	}

	if !data.HasCookie {
		t.Error("Expected HasCookie to be true")
	}

	expectedHeaders := []string{"Host", "Connection", "User-Agent", "Accept", "Accept-Language", "Cookie", "Referer"}
	if len(data.HeaderOrder) != 7 {
		t.Errorf("Header count mismatch: want 7, got %d", len(data.HeaderOrder))
	}
	for i, h := range expectedHeaders {
		if i < len(data.HeaderOrder) && data.HeaderOrder[i] != h {
			t.Errorf("Header order mismatch at %d: want %s, got %s", i, h, data.HeaderOrder[i])
		}
	}

	if len(data.CookieFields) != 2 {
		t.Errorf("Cookie fields count mismatch: want 2, got %d", len(data.CookieFields))
	}

	if data.AcceptLanguage != "en-US,en;q=0.5" {
		t.Errorf("Accept-Language mismatch: want 'en-US,en;q=0.5', got %q", data.AcceptLanguage)
	}

	// Now compute JA4H
	ja4h := ComputeJA4H(data)
	t.Logf("JA4H for test request: %s", ja4h)

	// Validate format
	if !ValidateJA4H(ja4h) {
		t.Errorf("JA4H validation failed: %s", ja4h)
	}

	// Check JA4H_a: ge11c05 (GET, HTTP/1.1, cookie present, 5 headers excluding Cookie and Referer)
	// Headers: Host, Connection, User-Agent, Accept, Accept-Language (5 headers, Cookie and Referer excluded)
	if !strings.HasPrefix(ja4h, "ge11c05_") {
		t.Errorf("JA4H_a mismatch: expected prefix 'ge11c05_', got %s", ja4h[:8])
	}
}

func TestParseCookieFieldNames(t *testing.T) {
	tests := []struct {
		name   string
		cookie string
		want   []string
	}{
		{
			name:   "Single cookie",
			cookie: "session=abc123",
			want:   []string{"session"},
		},
		{
			name:   "Multiple cookies",
			cookie: "session=abc; user=john; token=xyz",
			want:   []string{"session", "user", "token"},
		},
		{
			name:   "Cookies with spaces",
			cookie: "  session = abc ; user = john  ",
			want:   []string{"session", "user"},
		},
		{
			name:   "Cookie without value",
			cookie: "flag; name=value",
			want:   []string{"flag", "name"},
		},
		{
			name:   "Empty string",
			cookie: "",
			want:   []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseCookieFieldNames(tt.cookie)
			if len(got) == 0 && len(tt.want) == 0 {
				return // Both empty, that's fine
			}
			if !equalStringSlices(got, tt.want) {
				t.Errorf("parseCookieFieldNames(%q) = %v, want %v", tt.cookie, got, tt.want)
			}
		})
	}
}

func TestHTTPVersionCode(t *testing.T) {
	tests := []struct {
		version string
		want    string
	}{
		{"HTTP/1.0", "10"},
		{"HTTP/1.1", "11"},
		{"HTTP/2.0", "20"},
		{"HTTP/2", "20"},
		{"HTTP/3", "30"},
		{"1.1", "11"},
		{"2", "20"},
		{"unknown", "00"},
		{"", "00"},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			got := httpVersionCode(tt.version)
			if got != tt.want {
				t.Errorf("httpVersionCode(%q) = %q, want %q", tt.version, got, tt.want)
			}
		})
	}
}

func TestValidateJA4H(t *testing.T) {
	tests := []struct {
		fingerprint string
		valid       bool
	}{
		{"ge11c05_d6a4a8d71109_e0a89e3e939d_a82c9fccc4f7", true}, // 7 char JA4H_a
		{"po11n10_000000000000_000000000000_000000000000", true},
		{"ge20n03_abcdef123456_123456abcdef_fedcba654321", true},
		{"invalid", false},
		{"ge11c05_d6a4a8d71109_e0a89e3e939d", false},             // Missing 4th part
		{"ge11c0_d6a4a8d71109_e0a89e3e939d_a82c9fccc4f7", false}, // JA4H_a too short (6 chars)
		{"ge11c055_d6a4a8d71109_e0a89e3e939d_a82c9fccc4f7", false}, // JA4H_a too long (8 chars)
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.fingerprint, func(t *testing.T) {
			got := ValidateJA4H(tt.fingerprint)
			if got != tt.valid {
				t.Errorf("ValidateJA4H(%q) = %v, want %v", tt.fingerprint, got, tt.valid)
			}
		})
	}
}

func TestComputeJA4HRaw(t *testing.T) {
	data := &HTTPData{
		Method:  "GET",
		Version: "HTTP/1.1",
		HeaderOrder: []string{
			"Host",
			"User-Agent",
			"Accept",
		},
		HasCookie:      false,
		CookieFields:   nil,
		AcceptLanguage: "en-US",
	}

	raw := ComputeJA4HRaw(data)
	t.Logf("JA4H_raw = %s", raw)

	// Should contain the actual header names, not hashes
	if !strings.Contains(raw, "Host,User-Agent,Accept") {
		t.Errorf("JA4H_raw should contain header names, got: %s", raw)
	}

	if !strings.Contains(raw, "en-US") {
		t.Errorf("JA4H_raw should contain Accept-Language value, got: %s", raw)
	}
}

func TestHeaderOrderPreservation(t *testing.T) {
	// Test that header order is preserved exactly as in wire format
	rawRequest := "GET / HTTP/1.1\r\n" +
		"Z-Custom-Header: first\r\n" +
		"A-Custom-Header: second\r\n" +
		"M-Custom-Header: third\r\n" +
		"Host: example.com\r\n" +
		"\r\n"

	headers, _, _ := ExtractHeaderOrder([]byte(rawRequest))

	expected := []string{"Z-Custom-Header", "A-Custom-Header", "M-Custom-Header", "Host"}
	if !equalStringSlices(headers, expected) {
		t.Errorf("Header order not preserved: want %v, got %v", expected, headers)
	}
}

// Helper function
func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

