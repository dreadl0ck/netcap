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

package http

import (
	"fmt"
	"path"

	"github.com/dreadl0ck/netcap/decoder/core"
	"github.com/dreadl0ck/netcap/decoder/stream/file"
)

// HTTPFileExtractor implements file extraction for HTTP transfers
type HTTPFileExtractor struct{}

// GetFileHandle generates a unique identifier for an HTTP file transfer
func (h *HTTPFileExtractor) GetFileHandle(conv *core.ConversationInfo, isOrigin bool, depth int) string {
	return fmt.Sprintf("HTTP-%s-%d-%v", conv.Ident, depth, isOrigin)
}

// DescribeFile returns a human-readable description of the HTTP file transfer
func (h *HTTPFileExtractor) DescribeFile(handle *file.FileHandle) string {
	return fmt.Sprintf("HTTP transfer on connection %s", handle.ConversationID)
}

// ExtractFile performs HTTP file extraction with enhanced metadata
func (h *HTTPFileExtractor) ExtractFile(conv *core.ConversationInfo, data []byte, metadata file.FileMetadata) error {
	// Check if HTTP file extraction is enabled
	if !file.IsProtocolEnabled("HTTP") {
		return nil
	}

	// Build source description
	source := "HTTP"
	if metadata.HTTPMethod != "" {
		source = fmt.Sprintf("HTTP %s", metadata.HTTPMethod)
		if metadata.HTTPURL != "" {
			source = fmt.Sprintf("%s %s", source, metadata.HTTPURL)
		}
	}
	if metadata.HTTPStatusCode > 0 {
		source = fmt.Sprintf("%s (Status: %d)", source, metadata.HTTPStatusCode)
	}

	filename := metadata.Filename
	if filename == "" && metadata.HTTPURL != "" {
		filename = path.Base(metadata.HTTPURL)
	}
	if filename == "" || filename == "/" {
		filename = "http-content"
	}

	return file.SaveFileEnhanced(
		conv,
		source,
		filename,
		nil, // no error
		data,
		metadata.Encoding,
		metadata.Host,
		metadata.ContentType,
		0,  // depth - could be enhanced to track pipelined requests
		"", // parent file ID
		metadata.FlowDirection,
	)
}

// ProtocolName returns the protocol name
func (h *HTTPFileExtractor) ProtocolName() string {
	return "HTTP"
}

// RegisterHTTPExtractor registers the HTTP file extractor
func init() {
	file.RegisterExtractor(&HTTPFileExtractor{})
}
