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

package smb

import (
	"fmt"
	"path/filepath"

	"github.com/dreadl0ck/netcap/decoder/core"
	"github.com/dreadl0ck/netcap/decoder/stream/file"
)

// SMBFileExtractor implements file extraction for SMB file share operations
type SMBFileExtractor struct{}

// GetFileHandle generates a unique identifier for an SMB file transfer
func (s *SMBFileExtractor) GetFileHandle(conv *core.ConversationInfo, isOrigin bool, depth int) string {
	return fmt.Sprintf("SMB-%s-%d-%v", conv.Ident, depth, isOrigin)
}

// DescribeFile returns a human-readable description of the SMB file transfer
func (s *SMBFileExtractor) DescribeFile(handle *file.FileHandle) string {
	return fmt.Sprintf("SMB transfer on connection %s", handle.ConversationID)
}

// ExtractFile performs SMB file extraction
func (s *SMBFileExtractor) ExtractFile(conv *core.ConversationInfo, data []byte, metadata file.FileMetadata) error {
	// Build source description
	source := "SMB"
	if metadata.SMBShare != "" {
		source = fmt.Sprintf("SMB \\\\%s\\%s", metadata.Host, metadata.SMBShare)
		if metadata.SMBPath != "" {
			source = fmt.Sprintf("%s\\%s", source, metadata.SMBPath)
		}
	}

	filename := metadata.Filename
	if filename == "" {
		filename = "smb-file"
	}

	// Clean the filename
	filename = filepath.Base(filename)

	return file.SaveFileEnhanced(
		conv,
		source,
		filename,
		nil, // no error
		data,
		metadata.Encoding,
		metadata.Host,
		metadata.ContentType,
		0,  // depth
		"", // parent file ID
		metadata.FlowDirection,
	)
}

// ProtocolName returns the protocol name
func (s *SMBFileExtractor) ProtocolName() string {
	return "SMB"
}

// RegisterSMBExtractor registers the SMB file extractor
func init() {
	file.RegisterExtractor(&SMBFileExtractor{})
}
