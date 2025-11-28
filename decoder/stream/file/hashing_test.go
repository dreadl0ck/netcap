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

func TestComputeHashes(t *testing.T) {
	testData := []byte("Hello, World! This is a test file for hashing.")

	hashes := ComputeHashes(testData)

	// Verify MD5
	if len(hashes.MD5) != 32 {
		t.Errorf("MD5 hash length incorrect: got %d, want 32", len(hashes.MD5))
	}

	// Verify SHA1
	if len(hashes.SHA1) != 40 {
		t.Errorf("SHA1 hash length incorrect: got %d, want 40", len(hashes.SHA1))
	}

	// Verify SHA256
	if len(hashes.SHA256) != 64 {
		t.Errorf("SHA256 hash length incorrect: got %d, want 64", len(hashes.SHA256))
	}

	// Verify hashes are hex encoded (lowercase)
	for _, c := range hashes.MD5 {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("MD5 hash contains invalid character: %c", c)
		}
	}
}

func TestStreamingHashWriter(t *testing.T) {
	// Create a temporary file
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.txt")

	f, err := os.Create(tmpFile)
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	writer := NewStreamingHashWriter(f)

	testData := []byte("Testing streaming hash computation")
	n, err := writer.Write(testData)
	if err != nil {
		t.Fatalf("Failed to write data: %v", err)
	}
	if n != len(testData) {
		t.Errorf("Wrote %d bytes, expected %d", n, len(testData))
	}

	hashes := writer.GetHashes()

	// Verify hashes are computed
	if len(hashes.MD5) != 32 {
		t.Errorf("MD5 hash length incorrect: got %d, want 32", len(hashes.MD5))
	}
	if len(hashes.SHA1) != 40 {
		t.Errorf("SHA1 hash length incorrect: got %d, want 40", len(hashes.SHA1))
	}
	if len(hashes.SHA256) != 64 {
		t.Errorf("SHA256 hash length incorrect: got %d, want 64", len(hashes.SHA256))
	}

	writer.Close()

	// Compare with direct hash computation
	directHashes := ComputeHashes(testData)
	if hashes.MD5 != directHashes.MD5 {
		t.Errorf("MD5 mismatch: streaming=%s, direct=%s", hashes.MD5, directHashes.MD5)
	}
	if hashes.SHA1 != directHashes.SHA1 {
		t.Errorf("SHA1 mismatch: streaming=%s, direct=%s", hashes.SHA1, directHashes.SHA1)
	}
	if hashes.SHA256 != directHashes.SHA256 {
		t.Errorf("SHA256 mismatch: streaming=%s, direct=%s", hashes.SHA256, directHashes.SHA256)
	}
}

func TestComputeFileHashes(t *testing.T) {
	// Create a temporary file
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.txt")

	testData := []byte("File content for hash testing")
	if err := os.WriteFile(tmpFile, testData, 0644); err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	hashes, err := ComputeFileHashes(tmpFile)
	if err != nil {
		t.Fatalf("Failed to compute file hashes: %v", err)
	}

	// Compare with direct computation
	directHashes := ComputeHashes(testData)
	if hashes.MD5 != directHashes.MD5 {
		t.Errorf("MD5 mismatch: file=%s, direct=%s", hashes.MD5, directHashes.MD5)
	}
	if hashes.SHA1 != directHashes.SHA1 {
		t.Errorf("SHA1 mismatch: file=%s, direct=%s", hashes.SHA1, directHashes.SHA1)
	}
	if hashes.SHA256 != directHashes.SHA256 {
		t.Errorf("SHA256 mismatch: file=%s, direct=%s", hashes.SHA256, directHashes.SHA256)
	}
}

func BenchmarkComputeHashes(b *testing.B) {
	testData := make([]byte, 1024*1024) // 1MB
	for i := range testData {
		testData[i] = byte(i % 256)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ComputeHashes(testData)
	}
}
