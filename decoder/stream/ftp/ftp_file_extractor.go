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
		0,  // depth
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
