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

package collector

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestIdentifyFileTypeByMagic tests the magic number detection
func TestIdentifyFileTypeByMagic(t *testing.T) {
	tests := []struct {
		name         string
		magic        uint32
		expectKnown  bool
		expectedName string
	}{
		{
			name:         "PCAP little-endian",
			magic:        0xa1b2c3d4,
			expectKnown:  true,
			expectedName: "PCAP",
		},
		{
			name:         "PCAPNG",
			magic:        0x0a0d0d0a,
			expectKnown:  true,
			expectedName: "PCAPNG",
		},
		{
			name:         "ZIP",
			magic:        0x504b0304,
			expectKnown:  true,
			expectedName: "ZIP",
		},
		{
			name:        "Unknown magic (5d8cfe2e)",
			magic:       0x5d8cfe2e,
			expectKnown: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a temporary file with the magic number
			tmpDir := t.TempDir()
			tmpFile := filepath.Join(tmpDir, "test.pcap")

			f, err := os.Create(tmpFile)
			if err != nil {
				t.Fatal(err)
			}

			// Write magic number
			magicBytes := make([]byte, 4)
			binary.LittleEndian.PutUint32(magicBytes, tt.magic)
			_, err = f.Write(magicBytes)
			if err != nil {
				f.Close()
				t.Fatal(err)
			}
			f.Close()

			// Test identification
			magic, fileInfo, err := identifyFileTypeByMagic(tmpFile)
			if err != nil {
				t.Fatal(err)
			}

			if tt.expectKnown {
				if fileInfo == nil {
					t.Errorf("Expected to identify file type, but got nil")
				} else if fileInfo.name != tt.expectedName {
					t.Errorf("Expected %s, got %s", tt.expectedName, fileInfo.name)
				}
			} else {
				if fileInfo != nil {
					t.Errorf("Expected unknown file type, but got %s", fileInfo.name)
				}
			}

			t.Logf("Magic: 0x%08x, FileInfo: %v", magic, fileInfo)
		})
	}
}

// TestEnhancePcapError tests the enhanced error messages
func TestEnhancePcapError(t *testing.T) {
	tests := []struct {
		name          string
		magic         uint32
		shouldContain []string
	}{
		{
			name:  "ZIP file",
			magic: 0x504b0304,
			shouldContain: []string{
				"ZIP",
				"Extract the PCAP/PCAPNG file first",
				"0x504b0304",
			},
		},
		{
			name:  "Unknown magic (5d8cfe2e)",
			magic: 0x5d8cfe2e,
			shouldContain: []string{
				"Unknown or unsupported format",
				"0x5d8cfe2e",
				"Possible causes",
				"File is corrupted",
			},
		},
		{
			name:  "Unknown magic (73726576)",
			magic: 0x73726576,
			shouldContain: []string{
				"Unknown or unsupported format",
				"0x73726576",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a temporary file with the magic number
			tmpDir := t.TempDir()
			tmpFile := filepath.Join(tmpDir, "test.pcap")

			f, err := os.Create(tmpFile)
			if err != nil {
				t.Fatal(err)
			}

			// Write magic number
			magicBytes := make([]byte, 4)
			binary.LittleEndian.PutUint32(magicBytes, tt.magic)
			_, err = f.Write(magicBytes)
			if err != nil {
				f.Close()
				t.Fatal(err)
			}
			f.Close()

			// Test enhanced error
			originalErr := fmt.Errorf("Unknown magic %x", tt.magic)
			enhancedErr := enhancePcapError(tmpFile, originalErr)

			errMsg := enhancedErr.Error()
			t.Logf("Enhanced error message:\n%s", errMsg)

			for _, shouldContain := range tt.shouldContain {
				if !contains(errMsg, shouldContain) {
					t.Errorf("Error message should contain '%s', but doesn't.\nFull error: %s",
						shouldContain, errMsg)
				}
			}
		})
	}
}

// contains checks if a string contains a substring (case-insensitive would be better, but this is simple)
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) &&
		(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
			containsHelper(s, substr)))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
