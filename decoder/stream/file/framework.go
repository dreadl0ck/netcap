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

