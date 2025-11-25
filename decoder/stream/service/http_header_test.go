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

