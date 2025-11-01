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
	"net/http"
	"testing"
)

func TestGetClientIP(t *testing.T) {
	tests := []struct {
		name          string
		remoteAddr    string
		xForwardedFor string
		xRealIP       string
		expectedIP    string
		description   string
	}{
		{
			name:        "IPv4 with port",
			remoteAddr:  "192.168.1.100:54321",
			expectedIP:  "192.168.1.100",
			description: "Should strip port from IPv4 address",
		},
		{
			name:        "IPv6 with port",
			remoteAddr:  "[2001:db8::1]:54321",
			expectedIP:  "2001:db8::1",
			description: "Should strip port from IPv6 address",
		},
		{
			name:        "Different IPv4 with same IP different port",
			remoteAddr:  "192.168.1.100:12345",
			expectedIP:  "192.168.1.100",
			description: "Different port should result in same IP",
		},
		{
			name:          "X-Forwarded-For header single IP",
			remoteAddr:    "192.168.1.1:54321",
			xForwardedFor: "203.0.113.1",
			expectedIP:    "203.0.113.1",
			description:   "Should use X-Forwarded-For when present",
		},
		{
			name:          "X-Forwarded-For header multiple IPs",
			remoteAddr:    "192.168.1.1:54321",
			xForwardedFor: "203.0.113.1, 198.51.100.1, 192.168.1.1",
			expectedIP:    "203.0.113.1",
			description:   "Should extract first IP from X-Forwarded-For chain",
		},
		{
			name:        "X-Real-IP header",
			remoteAddr:  "192.168.1.1:54321",
			xRealIP:     "203.0.113.1",
			expectedIP:  "203.0.113.1",
			description: "Should use X-Real-IP when present",
		},
		{
			name:          "X-Forwarded-For takes precedence over X-Real-IP",
			remoteAddr:    "192.168.1.1:54321",
			xForwardedFor: "203.0.113.1",
			xRealIP:       "198.51.100.1",
			expectedIP:    "203.0.113.1",
			description:   "X-Forwarded-For should have priority",
		},
		{
			name:        "Localhost IPv4",
			remoteAddr:  "127.0.0.1:54321",
			expectedIP:  "127.0.0.1",
			description: "Should handle localhost correctly",
		},
		{
			name:        "Localhost IPv6",
			remoteAddr:  "[::1]:54321",
			expectedIP:  "::1",
			description: "Should handle IPv6 localhost correctly",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock HTTP request
			req, err := http.NewRequest("GET", "http://example.com", nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			// Set RemoteAddr
			req.RemoteAddr = tt.remoteAddr

			// Set headers if provided
			if tt.xForwardedFor != "" {
				req.Header.Set("X-Forwarded-For", tt.xForwardedFor)
			}
			if tt.xRealIP != "" {
				req.Header.Set("X-Real-IP", tt.xRealIP)
			}

			// Call getClientIP
			result := getClientIP(req)

			// Verify result
			if result != tt.expectedIP {
				t.Errorf("%s: expected IP %s, got %s", tt.description, tt.expectedIP, result)
			}
		})
	}
}

// TestGetClientIP_SessionsByIP verifies that sessions are tracked per IP, not per IP:port
func TestGetClientIP_SessionsByIP(t *testing.T) {
	// Test that the same IP with different ports returns the same IP value
	req1, _ := http.NewRequest("GET", "http://example.com", nil)
	req1.RemoteAddr = "192.168.1.100:54321"

	req2, _ := http.NewRequest("GET", "http://example.com", nil)
	req2.RemoteAddr = "192.168.1.100:12345"

	req3, _ := http.NewRequest("GET", "http://example.com", nil)
	req3.RemoteAddr = "192.168.1.100:99999"

	ip1 := getClientIP(req1)
	ip2 := getClientIP(req2)
	ip3 := getClientIP(req3)

	if ip1 != ip2 || ip2 != ip3 {
		t.Errorf("Same IP with different ports should return same IP value. Got: %s, %s, %s", ip1, ip2, ip3)
	}

	if ip1 != "192.168.1.100" {
		t.Errorf("Expected IP 192.168.1.100, got %s", ip1)
	}
}
