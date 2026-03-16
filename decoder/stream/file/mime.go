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
	"bytes"
	"net/http"
)

// MIMESignature represents a file signature for magic number detection
type MIMESignature struct {
	Magic  []byte
	Offset int
	MIME   string
	Ext    string
}

// Common file signatures for enhanced MIME detection
var signatures = []MIMESignature{
	// Images
	{Magic: []byte{0xFF, 0xD8, 0xFF}, Offset: 0, MIME: "image/jpeg", Ext: ".jpg"},
	{Magic: []byte{0x89, 0x50, 0x4E, 0x47}, Offset: 0, MIME: "image/png", Ext: ".png"},
	{Magic: []byte{0x47, 0x49, 0x46, 0x38}, Offset: 0, MIME: "image/gif", Ext: ".gif"},
	{Magic: []byte{0x42, 0x4D}, Offset: 0, MIME: "image/bmp", Ext: ".bmp"},
	{Magic: []byte{0x00, 0x00, 0x01, 0x00}, Offset: 0, MIME: "image/x-icon", Ext: ".ico"},

	// Documents
	{Magic: []byte{0x25, 0x50, 0x44, 0x46}, Offset: 0, MIME: "application/pdf", Ext: ".pdf"},
	{Magic: []byte{0x50, 0x4B, 0x03, 0x04}, Offset: 0, MIME: "application/zip", Ext: ".zip"},
	{Magic: []byte{0x50, 0x4B, 0x05, 0x06}, Offset: 0, MIME: "application/zip", Ext: ".zip"},
	{Magic: []byte{0x50, 0x4B, 0x07, 0x08}, Offset: 0, MIME: "application/zip", Ext: ".zip"},

	// Office documents (OOXML)
	{Magic: []byte{0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x06, 0x00}, Offset: 0, MIME: "application/vnd.openxmlformats-officedocument", Ext: ".docx"},

	// Archives
	{Magic: []byte{0x1F, 0x8B}, Offset: 0, MIME: "application/gzip", Ext: ".gz"},
	{Magic: []byte{0x42, 0x5A, 0x68}, Offset: 0, MIME: "application/x-bzip2", Ext: ".bz2"},
	{Magic: []byte{0x52, 0x61, 0x72, 0x21}, Offset: 0, MIME: "application/x-rar-compressed", Ext: ".rar"},
	{Magic: []byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}, Offset: 0, MIME: "application/x-7z-compressed", Ext: ".7z"},

	// Executables
	{Magic: []byte{0x4D, 0x5A}, Offset: 0, MIME: "application/x-msdownload", Ext: ".exe"},
	{Magic: []byte{0x7F, 0x45, 0x4C, 0x46}, Offset: 0, MIME: "application/x-elf", Ext: ".elf"},
	{Magic: []byte{0xCA, 0xFE, 0xBA, 0xBE}, Offset: 0, MIME: "application/x-mach-binary", Ext: ".macho"},

	// Media
	{Magic: []byte{0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70}, Offset: 0, MIME: "video/mp4", Ext: ".mp4"},
	{Magic: []byte{0x00, 0x00, 0x00, 0x1C, 0x66, 0x74, 0x79, 0x70}, Offset: 0, MIME: "video/mp4", Ext: ".mp4"},
	{Magic: []byte{0x49, 0x44, 0x33}, Offset: 0, MIME: "audio/mpeg", Ext: ".mp3"},
	{Magic: []byte{0xFF, 0xFB}, Offset: 0, MIME: "audio/mpeg", Ext: ".mp3"},

	// Scripts
	{Magic: []byte{0x23, 0x21, 0x2F}, Offset: 0, MIME: "text/x-shellscript", Ext: ".sh"},      // #!
	{Magic: []byte{0x3C, 0x3F, 0x70, 0x68, 0x70}, Offset: 0, MIME: "text/x-php", Ext: ".php"}, // <?php
}

// DetectContentType performs enhanced MIME type detection using magic numbers
// Returns the MIME type and a boolean indicating if detection was accurate
func DetectContentType(data []byte) (string, bool) {
	if len(data) == 0 {
		return "application/octet-stream", false
	}

	// Try magic number detection first (more accurate)
	for _, sig := range signatures {
		if len(data) >= sig.Offset+len(sig.Magic) {
			if bytes.Equal(data[sig.Offset:sig.Offset+len(sig.Magic)], sig.Magic) {
				return sig.MIME, true
			}
		}
	}

	// Check for text patterns
	if isTextContent(data) {
		// Check for HTML
		if bytes.Contains(data[:min(512, len(data))], []byte("<html")) ||
			bytes.Contains(data[:min(512, len(data))], []byte("<!DOCTYPE")) {
			return "text/html", true
		}

		// Check for XML
		if bytes.HasPrefix(data, []byte("<?xml")) {
			return "text/xml", true
		}

		// Check for JSON
		trimmed := bytes.TrimSpace(data[:min(100, len(data))])
		if (bytes.HasPrefix(trimmed, []byte("{")) && bytes.Contains(data, []byte(":"))) ||
			bytes.HasPrefix(trimmed, []byte("[")) {
			return "application/json", true
		}

		// Generic text
		return "text/plain", false
	}

	// Fallback to Go's http.DetectContentType
	return http.DetectContentType(data), false
}

// isTextContent checks if data appears to be text
func isTextContent(data []byte) bool {
	if len(data) == 0 {
		return false
	}

	// Sample first 512 bytes
	sample := data
	if len(data) > 512 {
		sample = data[:512]
	}

	// Count non-printable characters
	nonPrintable := 0
	for _, b := range sample {
		// Check if byte is printable ASCII or common whitespace
		if b < 0x20 && b != 0x09 && b != 0x0A && b != 0x0D {
			nonPrintable++
		} else if b > 0x7E && b < 0x80 {
			nonPrintable++
		}
	}

	// If more than 10% non-printable, it's likely binary
	return float64(nonPrintable)/float64(len(sample)) < 0.1
}
