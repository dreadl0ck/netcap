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
	"testing"
)

func TestDetectContentType(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		wantMIME string
		wantAcc  bool // Whether detection should be accurate
	}{
		{
			name:     "JPEG image",
			data:     []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46},
			wantMIME: "image/jpeg",
			wantAcc:  true,
		},
		{
			name:     "PNG image",
			data:     []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A},
			wantMIME: "image/png",
			wantAcc:  true,
		},
		{
			name:     "GIF image",
			data:     []byte{0x47, 0x49, 0x46, 0x38, 0x39, 0x61},
			wantMIME: "image/gif",
			wantAcc:  true,
		},
		{
			name:     "PDF document",
			data:     []byte{0x25, 0x50, 0x44, 0x46, 0x2D, 0x31, 0x2E},
			wantMIME: "application/pdf",
			wantAcc:  true,
		},
		{
			name:     "ZIP archive",
			data:     []byte{0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00},
			wantMIME: "application/zip",
			wantAcc:  true,
		},
		{
			name:     "GZIP archive",
			data:     []byte{0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00},
			wantMIME: "application/gzip",
			wantAcc:  true,
		},
		{
			name:     "Windows executable",
			data:     []byte{0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00},
			wantMIME: "application/x-msdownload",
			wantAcc:  true,
		},
		{
			name:     "ELF executable",
			data:     []byte{0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00},
			wantMIME: "application/x-elf",
			wantAcc:  true,
		},
		{
			name:     "HTML text",
			data:     []byte("<html><head><title>Test</title></head></html>"),
			wantMIME: "text/html",
			wantAcc:  true,
		},
		{
			name:     "XML text",
			data:     []byte("<?xml version=\"1.0\"?><root></root>"),
			wantMIME: "text/xml",
			wantAcc:  true,
		},
		{
			name:     "JSON data",
			data:     []byte(`{"key": "value", "number": 123}`),
			wantMIME: "application/json",
			wantAcc:  true,
		},
		{
			name:     "Plain text",
			data:     []byte("This is just plain text content without any special markers."),
			wantMIME: "text/plain",
			wantAcc:  false,
		},
		{
			name:     "Empty data",
			data:     []byte{},
			wantMIME: "application/octet-stream",
			wantAcc:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotMIME, gotAcc := DetectContentType(tt.data)

			if gotMIME != tt.wantMIME {
				t.Errorf("DetectContentType() MIME = %v, want %v", gotMIME, tt.wantMIME)
			}
			if gotAcc != tt.wantAcc {
				t.Errorf("DetectContentType() accuracy = %v, want %v", gotAcc, tt.wantAcc)
			}
		})
	}
}

func TestIsTextContent(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{
			name: "Plain ASCII text",
			data: []byte("Hello, World! This is plain text."),
			want: true,
		},
		{
			name: "Text with newlines",
			data: []byte("Line 1\nLine 2\nLine 3"),
			want: true,
		},
		{
			name: "Binary data (JPEG)",
			data: []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46},
			want: false,
		},
		{
			name: "Binary data (random bytes)",
			data: []byte{0x00, 0x01, 0x02, 0x03, 0xFE, 0xFF, 0x80, 0x90},
			want: false,
		},
		{
			name: "Empty data",
			data: []byte{},
			want: false,
		},
		{
			name: "HTML markup",
			data: []byte("<html><body><p>Text</p></body></html>"),
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isTextContent(tt.data); got != tt.want {
				t.Errorf("isTextContent() = %v, want %v", got, tt.want)
			}
		})
	}
}

func BenchmarkDetectContentType(b *testing.B) {
	testData := []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46} // JPEG
	testData = append(testData, make([]byte, 1024)...)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DetectContentType(testData)
	}
}
