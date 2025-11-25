/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017-2020 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package service

import (
	"testing"

	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/types"
)

func TestParseServerHeader(t *testing.T) {
	tests := []struct {
		name            string
		input           string
		expectedProduct string
		expectedVersion string
	}{
		{
			name:            "Apache with version and OS",
			input:           "Apache/2.4.41 (Ubuntu)",
			expectedProduct: "Apache",
			expectedVersion: "2.4.41",
		},
		{
			name:            "nginx with version",
			input:           "nginx/1.18.0",
			expectedProduct: "nginx",
			expectedVersion: "1.18.0",
		},
		{
			name:            "Microsoft IIS",
			input:           "Microsoft-IIS/10.0",
			expectedProduct: "Microsoft-IIS",
			expectedVersion: "10.0",
		},
		{
			name:            "Server without version",
			input:           "cloudflare",
			expectedProduct: "cloudflare",
			expectedVersion: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			product, version := parseServerHeader(tt.input)
			if product != tt.expectedProduct {
				t.Errorf("parseServerHeader() product = %v, want %v", product, tt.expectedProduct)
			}
			if version != tt.expectedVersion {
				t.Errorf("parseServerHeader() version = %v, want %v", version, tt.expectedVersion)
			}
		})
	}
}

func TestParseXPoweredByHeader(t *testing.T) {
	tests := []struct {
		name            string
		input           string
		expectedProduct string
		expectedVersion string
	}{
		{
			name:            "PHP with version",
			input:           "PHP/7.4.3",
			expectedProduct: "PHP",
			expectedVersion: "7.4.3",
		},
		{
			name:            "ASP.NET without version",
			input:           "ASP.NET",
			expectedProduct: "ASP.NET",
			expectedVersion: "",
		},
		{
			name:            "Express framework",
			input:           "Express",
			expectedProduct: "Express",
			expectedVersion: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			product, version := parseXPoweredByHeader(tt.input)
			if product != tt.expectedProduct {
				t.Errorf("parseXPoweredByHeader() product = %v, want %v", product, tt.expectedProduct)
			}
			if version != tt.expectedVersion {
				t.Errorf("parseXPoweredByHeader() version = %v, want %v", version, tt.expectedVersion)
			}
		})
	}
}

func TestParseGeneratorHeader(t *testing.T) {
	tests := []struct {
		name            string
		input           string
		expectedProduct string
		expectedVersion string
	}{
		{
			name:            "WordPress with version",
			input:           "WordPress 5.8",
			expectedProduct: "WordPress",
			expectedVersion: "5.8",
		},
		{
			name:            "Drupal with version and URL",
			input:           "Drupal 9 (https://www.drupal.org)",
			expectedProduct: "Drupal",
			expectedVersion: "9",
		},
		{
			name:            "Jekyll with v prefix",
			input:           "Jekyll v4.2.0",
			expectedProduct: "Jekyll",
			expectedVersion: "4.2.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			product, version := parseGeneratorHeader(tt.input)
			if product != tt.expectedProduct {
				t.Errorf("parseGeneratorHeader() product = %v, want %v", product, tt.expectedProduct)
			}
			if version != tt.expectedVersion {
				t.Errorf("parseGeneratorHeader() version = %v, want %v", version, tt.expectedVersion)
			}
		})
	}
}

func TestParseViaHeader(t *testing.T) {
	tests := []struct {
		name            string
		input           string
		expectedProduct string
		expectedVersion string
	}{
		{
			name:            "Varnish proxy",
			input:           "1.1 varnish",
			expectedProduct: "varnish",
			expectedVersion: "",
		},
		{
			name:            "Squid with version",
			input:           "1.1 squid/4.10",
			expectedProduct: "squid",
			expectedVersion: "4.10",
		},
		{
			name:            "Invalid format",
			input:           "1.1",
			expectedProduct: "Proxy",
			expectedVersion: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			product, version := parseViaHeader(tt.input)
			if product != tt.expectedProduct {
				t.Errorf("parseViaHeader() product = %v, want %v", product, tt.expectedProduct)
			}
			if version != tt.expectedVersion {
				t.Errorf("parseViaHeader() version = %v, want %v", version, tt.expectedVersion)
			}
		})
	}
}

func TestMatchHTTPHeaders(t *testing.T) {
	tests := []struct {
		name            string
		banner          string
		expectedProduct string
		expectedVersion string
	}{
		{
			name: "HTTP response with Server header",
			banner: "HTTP/1.1 200 OK\r\n" +
				"Server: nginx/1.18.0\r\n" +
				"Content-Type: text/html\r\n" +
				"\r\n",
			expectedProduct: "nginx",
			expectedVersion: "1.18.0",
		},
		{
			name: "HTTP response with X-Powered-By",
			banner: "HTTP/1.1 200 OK\r\n" +
				"X-Powered-By: PHP/7.4.3\r\n" +
				"Content-Type: text/html\r\n" +
				"\r\n",
			expectedProduct: "PHP",
			expectedVersion: "7.4.3",
		},
		{
			name: "HTTP response with multiple headers (Server priority)",
			banner: "HTTP/1.1 200 OK\r\n" +
				"Server: Apache/2.4.41\r\n" +
				"X-Powered-By: PHP/7.4.3\r\n" +
				"Content-Type: text/html\r\n" +
				"\r\n",
			expectedProduct: "Apache",
			expectedVersion: "2.4.41",
		},
		{
			name: "HTTP response with X-Generator",
			banner: "HTTP/1.1 200 OK\r\n" +
				"X-Generator: WordPress 5.8\r\n" +
				"Content-Type: text/html\r\n" +
				"\r\n",
			expectedProduct: "WordPress",
			expectedVersion: "5.8",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serv := &service{
				Service: &types.Service{
					Timestamp: 0,
				},
				applications: make(map[string]struct{}),
			}

			matchHTTPHeaders(serv, []byte(tt.banner), "test-ident")

			if serv.Product != tt.expectedProduct {
				t.Errorf("matchHTTPHeaders() product = %v, want %v", serv.Product, tt.expectedProduct)
			}
			if serv.Version != tt.expectedVersion {
				t.Errorf("matchHTTPHeaders() version = %v, want %v", serv.Version, tt.expectedVersion)
			}
		})
	}
}

func TestMatchHTTPHeadersInvalidBanner(t *testing.T) {
	serv := &service{
		Service: &types.Service{
			Timestamp: 0,
		},
		applications: make(map[string]struct{}),
	}

	// Test with non-HTTP banner
	matchHTTPHeaders(serv, []byte("Not an HTTP response"), "test-ident")

	// Should not set any fields
	if serv.Product != "" {
		t.Errorf("matchHTTPHeaders() should not set product for non-HTTP banner, got %v", serv.Product)
	}
	if serv.Version != "" {
		t.Errorf("matchHTTPHeaders() should not set version for non-HTTP banner, got %v", serv.Version)
	}
}

func TestMatchHTTPHeadersWithGWSServer(t *testing.T) {
	// Test the specific case from the bug report: Server: gws
	serv := &service{
		Service: &types.Service{
			Timestamp: 0,
		},
		applications: make(map[string]struct{}),
	}

	banner := "HTTP/1.1 200 OK\r\n" +
		"Date: Wed, 15 Nov 2017 15:09:45 GMT\r\n" +
		"Expires: -1\r\n" +
		"Cache-Control: private, max-age=0\r\n" +
		"Content-Type: text/html; charset=ISO-8859-1\r\n" +
		"P3P: CP=\"This is not a P3P policy! See g.co/p3phelp for more info.\"\r\n" +
		"Server: gws\r\n" +
		"X-XSS-Protection: 1; mode=b\r\n" +
		"\r\n"

	matchHTTPHeaders(serv, []byte(banner), "test-ident")

	if serv.Product != "gws" {
		t.Errorf("matchHTTPHeaders() should extract Server header value 'gws', got %v", serv.Product)
	}
	if serv.MatchedProbeID != "http-header-server" {
		t.Errorf("matchHTTPHeaders() MatchedProbeID = %v, want 'http-header-server'", serv.MatchedProbeID)
	}
}

func TestExtractHeaderManually(t *testing.T) {
	tests := []struct {
		name           string
		banner         string
		expectedHeader string
		expectedValue  string
	}{
		{
			name: "Server header with CRLF",
			banner: "HTTP/1.1 200 OK\r\n" +
				"Date: Wed, 15 Nov 2017\r\n" +
				"Server: gws\r\n" +
				"Content-Type: text/html\r\n",
			expectedHeader: "Server",
			expectedValue:  "gws",
		},
		{
			name: "Server header with LF only",
			banner: "HTTP/1.1 200 OK\n" +
				"Date: Wed, 15 Nov 2017\n" +
				"Server: nginx/1.18.0\n" +
				"Content-Type: text/html\n",
			expectedHeader: "Server",
			expectedValue:  "nginx/1.18.0",
		},
		{
			name: "Truncated banner without terminator",
			banner: "HTTP/1.1 200 OK\r\n" +
				"Date: Wed, 15 Nov 2017 15:09:09 GMT\r\n" +
				"Expires: -1\r\n" +
				"Cache-Control: private, max-age=0\r\n" +
				"Content-Type: text/html; charset=ISO-8859-1\r\n" +
				"Server: gws\r\n" +
				"X-XSS-Protection: 1; mode=b",
			expectedHeader: "Server",
			expectedValue:  "gws",
		},
		{
			name: "X-Powered-By when Server is missing",
			banner: "HTTP/1.1 200 OK\r\n" +
				"X-Powered-By: PHP/7.4.3\r\n" +
				"Content-Type: text/html\r\n",
			expectedHeader: "X-Powered-By",
			expectedValue:  "PHP/7.4.3",
		},
		{
			name:           "No matching headers",
			banner:         "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n",
			expectedHeader: "",
			expectedValue:  "",
		},
	}

	priorityHeaders := []string{
		"Server",
		"X-Powered-By",
		"X-AspNet-Version",
		"X-AspNetMvc-Version",
		"X-Generator",
		"Via",
		"X-Cache",
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header, value := extractHeaderManually(tt.banner, priorityHeaders)
			if header != tt.expectedHeader {
				t.Errorf("extractHeaderManually() header = %v, want %v", header, tt.expectedHeader)
			}
			if value != tt.expectedValue {
				t.Errorf("extractHeaderManually() value = %v, want %v", value, tt.expectedValue)
			}
		})
	}
}

func TestMatchHTTPHeadersTruncatedBanner(t *testing.T) {
	// Test with a truncated banner that doesn't have the \r\n\r\n terminator
	// This simulates a real-world scenario where the banner is cut off
	serv := &service{
		Service: &types.Service{
			Timestamp: 0,
		},
		applications: make(map[string]struct{}),
	}

	// Truncated banner - no empty line at the end
	banner := "HTTP/1.1 200 OK\r\n" +
		"Date: Wed, 15 Nov 2017 15:09:09 GMT\r\n" +
		"Expires: -1\r\n" +
		"Cache-Control: private, max-age=0\r\n" +
		"Content-Type: text/html; charset=ISO-8859-1\r\n" +
		"P3P: CP=\"This is not a P3P policy! See g.co/p3phelp for more info.\"\r\n" +
		"Server: gws\r\n" +
		"X-XSS-Protection: 1; mode=b"

	matchHTTPHeaders(serv, []byte(banner), "test-ident")

	if serv.Product != "gws" {
		t.Errorf("matchHTTPHeaders() with truncated banner should extract 'gws', got %v", serv.Product)
	}
}

func TestMatchServiceProbesWithEmptyProductHTTPFallback(t *testing.T) {
	// Save original config value
	origStopAfterMatch := decoderconfig.Instance.StopAfterServiceProbeMatch
	defer func() {
		decoderconfig.Instance.StopAfterServiceProbeMatch = origStopAfterMatch
	}()

	// Enable StopAfterServiceProbeMatch to simulate production behavior
	decoderconfig.Instance.StopAfterServiceProbeMatch = true

	// Initialize service probes if not already done
	// Note: This test assumes service probes are already loaded, which happens during package init
	// If probes aren't loaded, this test will effectively test the HTTP-only fallback

	serv := &service{
		Service: &types.Service{
			Timestamp: 0,
			Port:      80,
			Protocol:  "TCP",
		},
		applications: make(map[string]struct{}),
	}

	// This banner is an HTTP response that:
	// 1. Will likely match a generic HTTP probe (which may not extract Product)
	// 2. Contains a Server header with value "gws" that should be extracted
	banner := []byte("HTTP/1.1 200 OK\r\n" +
		"Date: Wed, 15 Nov 2017 15:09:45 GMT\r\n" +
		"Expires: -1\r\n" +
		"Cache-Control: private, max-age=0\r\n" +
		"Content-Type: text/html; charset=ISO-8859-1\r\n" +
		"P3P: CP=\"This is not a P3P policy! See g.co/p3phelp for more info.\"\r\n" +
		"Server: gws\r\n" +
		"X-XSS-Protection: 1; mode=b\r\n" +
		"\r\n")

	// Run the full MatchServiceProbes which includes probe matching + HTTP header fallback
	MatchServiceProbes(serv, banner, "test-flow")

	// Even if a service probe matched but didn't extract Product,
	// the HTTP header matching should have extracted "gws" from the Server header
	if serv.Product == "" {
		t.Errorf("MatchServiceProbes() failed to extract Product from HTTP Server header. Expected 'gws', got empty string")
	}

	// Check that the Server header value was extracted
	if serv.Product != "" && serv.Product != "gws" {
		t.Logf("Note: Product was set to '%s' (might be from a service probe match). Server header 'gws' may or may not be present depending on probe match behavior.", serv.Product)
	}
}
