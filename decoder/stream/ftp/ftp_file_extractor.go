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

package ftp

import (
	"fmt"
	"path/filepath"

	"github.com/dreadl0ck/netcap/decoder/core"
	"github.com/dreadl0ck/netcap/decoder/stream/file"
)

// FTPFileExtractor implements file extraction for FTP DATA channel transfers
type FTPFileExtractor struct{}

// GetFileHandle generates a unique identifier for an FTP file transfer
func (f *FTPFileExtractor) GetFileHandle(conv *core.ConversationInfo, isOrigin bool, depth int) string {
	return fmt.Sprintf("FTP-%s-%d-%v", conv.Ident, depth, isOrigin)
}

// DescribeFile returns a human-readable description of the FTP file transfer
func (f *FTPFileExtractor) DescribeFile(handle *file.FileHandle) string {
	return fmt.Sprintf("FTP transfer on connection %s", handle.ConversationID)
}

// ExtractFile performs FTP file extraction
func (f *FTPFileExtractor) ExtractFile(conv *core.ConversationInfo, data []byte, metadata file.FileMetadata) error {
	// Check if FTP file extraction is enabled
	if !file.IsProtocolEnabled("FTP") {
		return nil
	}

	// Use the generic SaveFile utility with FTP-specific metadata
	source := "FTP DATA"
	if metadata.FTPCommand != "" {
		source = fmt.Sprintf("FTP %s", metadata.FTPCommand)
	}

	filename := metadata.Filename
	if filename == "" {
		filename = "ftp-transfer"
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
		0, // depth
		"", // parent file ID
		metadata.FlowDirection,
	)
}

// ProtocolName returns the protocol name
func (f *FTPFileExtractor) ProtocolName() string {
	return "FTP"
}

// RegisterFTPExtractor registers the FTP file extractor
func init() {
	file.RegisterExtractor(&FTPFileExtractor{})
}

