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

	"github.com/dreadl0ck/netcap/decoder/core"
)

// MockFileExtractor for testing
type MockFileExtractor struct {
	protocol string
}

func (m *MockFileExtractor) GetFileHandle(conv *core.ConversationInfo, isOrigin bool, depth int) string {
	return "mock-file-handle"
}

func (m *MockFileExtractor) DescribeFile(handle *FileHandle) string {
	return "Mock file description"
}

func (m *MockFileExtractor) ExtractFile(conv *core.ConversationInfo, data []byte, metadata FileMetadata) error {
	return nil
}

func (m *MockFileExtractor) ProtocolName() string {
	return m.protocol
}

func TestRegisterExtractor(t *testing.T) {
	// Clear registry for testing
	registry.extractors = make(map[string]FileExtractor)

	mock := &MockFileExtractor{protocol: "TEST"}
	RegisterExtractor(mock)

	extractor, ok := GetExtractor("TEST")
	if !ok {
		t.Fatal("Failed to retrieve registered extractor")
	}

	if extractor.ProtocolName() != "TEST" {
		t.Errorf("Protocol name = %s, want TEST", extractor.ProtocolName())
	}
}

func TestGetExtractor_NotFound(t *testing.T) {
	// Clear registry for testing
	registry.extractors = make(map[string]FileExtractor)

	_, ok := GetExtractor("NONEXISTENT")
	if ok {
		t.Error("Should not find non-existent extractor")
	}
}

func TestListExtractors(t *testing.T) {
	// Clear registry for testing
	registry.extractors = make(map[string]FileExtractor)

	// Register multiple extractors
	protocols := []string{"HTTP", "FTP", "SMTP"}
	for _, proto := range protocols {
		RegisterExtractor(&MockFileExtractor{protocol: proto})
	}

	list := ListExtractors()
	if len(list) != len(protocols) {
		t.Errorf("Listed extractors = %d, want %d", len(list), len(protocols))
	}

	// Verify all protocols are listed
	found := make(map[string]bool)
	for _, proto := range list {
		found[proto] = true
	}

	for _, proto := range protocols {
		if !found[proto] {
			t.Errorf("Protocol %s not found in list", proto)
		}
	}
}

func TestFileHandle(t *testing.T) {
	handle := &FileHandle{
		ID:             "test-id",
		ConversationID: "conv-123",
		Protocol:       "HTTP",
		Timestamp:      1234567890,
		Depth:          0,
		IsComplete:     true,
		TotalBytes:     1024,
		SeenBytes:      1024,
		MissingBytes:   0,
	}

	if handle.ID != "test-id" {
		t.Errorf("Handle ID = %s, want test-id", handle.ID)
	}
	if !handle.IsComplete {
		t.Error("Handle should be complete")
	}
	if handle.MissingBytes != 0 {
		t.Errorf("Missing bytes = %d, want 0", handle.MissingBytes)
	}
}

func TestFileMetadata(t *testing.T) {
	metadata := FileMetadata{
		ConnectionUID:  "conn-123",
		FlowDirection:  "client_to_server",
		HTTPMethod:     "GET",
		HTTPStatusCode: 200,
		HTTPURL:        "/test.html",
		Filename:       "test.html",
		ContentType:    "text/html",
		Host:           "example.com",
		Encoding:       []string{"gzip"},
	}

	if metadata.FlowDirection != "client_to_server" {
		t.Errorf("Flow direction = %s, want client_to_server", metadata.FlowDirection)
	}
	if metadata.HTTPMethod != "GET" {
		t.Errorf("HTTP method = %s, want GET", metadata.HTTPMethod)
	}
	if metadata.HTTPStatusCode != 200 {
		t.Errorf("HTTP status code = %d, want 200", metadata.HTTPStatusCode)
	}
}
