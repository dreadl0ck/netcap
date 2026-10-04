/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package cryptoutils

import (
	"bytes"
	"crypto/md5"
	"testing"
)

func TestMD5Data(t *testing.T) {
	testCases := []struct {
		input    []byte
		expected [16]byte
	}{
		{
			input:    []byte(""),
			expected: md5.Sum([]byte("")),
		},
		{
			input:    []byte("hello"),
			expected: md5.Sum([]byte("hello")),
		},
		{
			input:    []byte("The quick brown fox jumps over the lazy dog"),
			expected: md5.Sum([]byte("The quick brown fox jumps over the lazy dog")),
		},
	}

	for i, tc := range testCases {
		result := MD5Data(tc.input)
		if !bytes.Equal(result, tc.expected[:]) {
			t.Errorf("Test %d: MD5 mismatch for input %q", i, tc.input)
		}
	}

	// Verify output length
	result := MD5Data([]byte("test"))
	if len(result) != 16 {
		t.Errorf("MD5 output length incorrect: got %d, expected 16", len(result))
	}
}

func TestRandomString(t *testing.T) {
	lengths := []int{0, 1, 5, 10, 20, 50, 100}

	for _, length := range lengths {
		result, err := RandomString(length)
		if err != nil {
			t.Errorf("RandomString(%d) failed: %v", length, err)
			continue
		}

		if len(result) != length {
			t.Errorf("RandomString(%d) returned string of length %d", length, len(result))
		}
	}

	// Verify randomness - two calls should produce different results
	str1, _ := RandomString(32)
	str2, _ := RandomString(32)
	if str1 == str2 {
		t.Error("Two RandomString calls should produce different results")
	}
}

func TestRandomStringCharacters(t *testing.T) {
	// Verify output contains only URL-safe base64 characters
	result, err := RandomString(100)
	if err != nil {
		t.Fatalf("RandomString failed: %v", err)
	}

	validChars := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_="
	for _, c := range result {
		found := false
		for _, v := range validChars {
			if c == v {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Invalid character in RandomString output: %c", c)
		}
	}
}

func BenchmarkMD5Data(b *testing.B) {
	data := bytes.Repeat([]byte("X"), 1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = MD5Data(data)
	}
}
