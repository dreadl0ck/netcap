/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package file

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	// Create a temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test-file-extraction.yml")

	configContent := `file_extraction:
  enabled: true
  protocols:
    http: true
    ftp: false
    smtp: true
  size_limits:
    max_file_size: 52428800
    include_missing_bytes: false
  hash_algorithms:
    md5: true
    sha1: false
    sha256: true
  mime_types:
    whitelist:
      - "application/pdf"
      - "application/zip"
    blacklist: []
  storage:
    organize_by_mime: true
    organize_by_protocol: false
  reassembly:
    enabled: true
    allow_sparse_files: false
`

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to create test config: %v", err)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	// Verify configuration loaded correctly
	if !cfg.FileExtraction.Enabled {
		t.Error("Enabled should be true")
	}
	if !cfg.FileExtraction.Protocols.HTTP {
		t.Error("HTTP should be enabled")
	}
	if cfg.FileExtraction.Protocols.FTP {
		t.Error("FTP should be disabled")
	}
	if cfg.FileExtraction.SizeLimits.MaxFileSize != 52428800 {
		t.Errorf("MaxFileSize = %d, want 52428800", cfg.FileExtraction.SizeLimits.MaxFileSize)
	}
	if cfg.FileExtraction.HashAlgorithms.SHA1 {
		t.Error("SHA1 should be disabled")
	}
	if len(cfg.FileExtraction.MimeTypes.Whitelist) != 2 {
		t.Errorf("Whitelist length = %d, want 2", len(cfg.FileExtraction.MimeTypes.Whitelist))
	}
}

func TestGetDefaultConfig(t *testing.T) {
	cfg := GetDefaultConfig()

	if !cfg.FileExtraction.Enabled {
		t.Error("Default config should have extraction enabled")
	}
	if !cfg.FileExtraction.Protocols.HTTP {
		t.Error("HTTP should be enabled by default")
	}
	if cfg.FileExtraction.SizeLimits.MaxFileSize != 104857600 {
		t.Errorf("Default max file size = %d, want 104857600", cfg.FileExtraction.SizeLimits.MaxFileSize)
	}
}

func TestIsProtocolEnabled(t *testing.T) {
	// Set a test configuration
	testCfg := GetDefaultConfig()
	testCfg.FileExtraction.Protocols.FTP = false
	testCfg.FileExtraction.Protocols.IRC = true
	SetGlobalConfig(testCfg)

	tests := []struct {
		protocol string
		want     bool
	}{
		{"HTTP", true},
		{"FTP", false},
		{"IRC", true}, // We set it to true above
		{"SMTP", true},
		{"UNKNOWN", false},
	}

	for _, tt := range tests {
		t.Run(tt.protocol, func(t *testing.T) {
			got := IsProtocolEnabled(tt.protocol)
			if got != tt.want {
				t.Errorf("IsProtocolEnabled(%s) = %v, want %v", tt.protocol, got, tt.want)
			}
		})
	}
}

func TestShouldExtractMimeType(t *testing.T) {
	// Test with whitelist
	testCfg := GetDefaultConfig()
	testCfg.FileExtraction.MimeTypes.Whitelist = []string{"application/pdf", "application/zip"}
	SetGlobalConfig(testCfg)

	if !ShouldExtractMimeType("application/pdf") {
		t.Error("PDF should be extracted (in whitelist)")
	}
	if ShouldExtractMimeType("text/html") {
		t.Error("HTML should not be extracted (not in whitelist)")
	}

	// Test with blacklist
	testCfg = GetDefaultConfig()
	testCfg.FileExtraction.MimeTypes.Whitelist = []string{} // Clear whitelist
	testCfg.FileExtraction.MimeTypes.Blacklist = []string{"text/html", "text/plain"}
	SetGlobalConfig(testCfg)

	if ShouldExtractMimeType("text/html") {
		t.Error("HTML should not be extracted (in blacklist)")
	}
	if !ShouldExtractMimeType("application/pdf") {
		t.Error("PDF should be extracted (not in blacklist)")
	}
}

func TestShouldComputeHash(t *testing.T) {
	testCfg := GetDefaultConfig()
	testCfg.FileExtraction.HashAlgorithms.SHA1 = false
	SetGlobalConfig(testCfg)

	tests := []struct {
		algorithm string
		want      bool
	}{
		{"MD5", true},
		{"SHA1", false},
		{"SHA256", true},
		{"UNKNOWN", false},
	}

	for _, tt := range tests {
		t.Run(tt.algorithm, func(t *testing.T) {
			got := ShouldComputeHash(tt.algorithm)
			if got != tt.want {
				t.Errorf("ShouldComputeHash(%s) = %v, want %v", tt.algorithm, got, tt.want)
			}
		})
	}
}

func TestConfigThreadSafety(t *testing.T) {
	// Test concurrent access to config
	done := make(chan bool)

	for i := 0; i < 10; i++ {
		go func() {
			cfg := GetGlobalConfig()
			_ = cfg.FileExtraction.Enabled
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}
