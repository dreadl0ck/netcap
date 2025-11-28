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
	"sync"

	"github.com/dreadl0ck/netcap/decoder/core"
)

// FileHandle represents a unique file being extracted from network traffic
type FileHandle struct {
	ID             string
	ConversationID string
	Protocol       string
	Timestamp      int64
	Depth          int
	IsComplete     bool
	TotalBytes     int64
	SeenBytes      int64
	MissingBytes   int64
	ParentFileID   string
}

// FileMetadata contains contextual information about an extracted file
type FileMetadata struct {
	// Network context
	ConnectionUID string
	FlowDirection string // "client_to_server" or "server_to_client"

	// Protocol-specific context
	HTTPMethod     string // For HTTP files
	HTTPStatusCode int
	HTTPURL        string
	FTPCommand     string // RETR/STOR
	SMBShare       string
	SMBPath        string

	// Content information
	Filename    string
	ContentType string
	Host        string
	Encoding    []string
}

// FileExtractor is the interface that protocol-specific extractors must implement
type FileExtractor interface {
	// GetFileHandle generates a unique identifier for a file in the conversation
	GetFileHandle(conv *core.ConversationInfo, isOrigin bool, depth int) string

	// DescribeFile returns a human-readable description of the file
	DescribeFile(handle *FileHandle) string

	// ExtractFile performs the actual file extraction
	ExtractFile(conv *core.ConversationInfo, data []byte, metadata FileMetadata) error

	// ProtocolName returns the name of the protocol this extractor handles
	ProtocolName() string
}

// extractorRegistry holds all registered file extractors
type extractorRegistry struct {
	mu         sync.RWMutex
	extractors map[string]FileExtractor
}

var registry = &extractorRegistry{
	extractors: make(map[string]FileExtractor),
}

// RegisterExtractor registers a file extractor for a specific protocol
func RegisterExtractor(extractor FileExtractor) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	registry.extractors[extractor.ProtocolName()] = extractor
}

// GetExtractor retrieves a file extractor for the given protocol
func GetExtractor(protocol string) (FileExtractor, bool) {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	extractor, ok := registry.extractors[protocol]
	return extractor, ok
}

// ListExtractors returns a list of all registered protocol extractors
func ListExtractors() []string {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	protocols := make([]string, 0, len(registry.extractors))
	for protocol := range registry.extractors {
		protocols = append(protocols, protocol)
	}
	return protocols
}
