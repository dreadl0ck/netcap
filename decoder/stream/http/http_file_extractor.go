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
