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

package webui

import (
	"strings"
	"testing"
)

// TestSanitizeFilename tests the sanitization of rule names for use as filenames.
// This is critical for preventing path traversal issues and filesystem errors when
// rule names contain special characters like forward slashes.
func TestSanitizeFilename(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "forward slash",
			input:    "RTP Audio/Video Stream Detected",
			expected: "RTP_Audio_Video_Stream_Detected",
		},
		{
			name:     "backslash",
			input:    "Windows\\Path\\Rule",
			expected: "Windows_Path_Rule",
		},
		{
			name:     "multiple special characters",
			input:    "Rule: Name (with) [special] {chars}!",
			expected: "Rule__Name__with___special___chars__",
		},
		{
			name:     "spaces",
			input:    "My Rule Name",
			expected: "My_Rule_Name",
		},
		{
			name:     "already safe",
			input:    "Safe_Rule_Name-123",
			expected: "Safe_Rule_Name-123",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "rule",
		},
		{
			name:     "only special characters",
			input:    "///:::***",
			expected: "_________",
		},
		{
			name:     "unicode characters",
			input:    "Rule_中文_Name",
			expected: "Rule____Name",
		},
		{
			name:     "dots and colons",
			input:    "DNS:A:Record.Query",
			expected: "DNS_A_Record_Query",
		},
		{
			name:     "ampersand and plus",
			input:    "HTTP&HTTPS+Rule",
			expected: "HTTP_HTTPS_Rule",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeFilename(tt.input)
			if result != tt.expected {
				t.Errorf("sanitizeFilename(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// TestSanitizeFilenamePropertiespreserves properties that safe filenames should have
func TestSanitizeFilenameProperties(t *testing.T) {
	tests := []string{
		"RTP Audio/Video Stream Detected",
		"Windows\\Path",
		"../../../etc/passwd",
		"Rule: Name",
		"",
		"!@#$%^&*()",
	}

	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			result := sanitizeFilename(input)

			// Must not be empty
			if result == "" {
				t.Error("sanitizeFilename returned empty string")
			}

			// Must not contain path separators
			if strings.Contains(result, "/") || strings.Contains(result, "\\") {
				t.Errorf("sanitizeFilename(%q) = %q contains path separator", input, result)
			}

			// Must only contain safe characters
			for _, r := range result {
				if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_') {
					t.Errorf("sanitizeFilename(%q) = %q contains unsafe character %q", input, result, string(r))
				}
			}
		})
	}
}

