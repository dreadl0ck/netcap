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

package irc

import (
	"fmt"
	"path/filepath"

	"github.com/dreadl0ck/netcap/decoder/core"
	"github.com/dreadl0ck/netcap/decoder/stream/file"
)

// IRCFileExtractor implements file extraction for IRC DCC file transfers
type IRCFileExtractor struct{}

// GetFileHandle generates a unique identifier for an IRC DCC file transfer
func (i *IRCFileExtractor) GetFileHandle(conv *core.ConversationInfo, isOrigin bool, depth int) string {
	return fmt.Sprintf("IRC-DCC-%s-%d-%v", conv.Ident, depth, isOrigin)
}

// DescribeFile returns a human-readable description of the IRC DCC transfer
func (i *IRCFileExtractor) DescribeFile(handle *file.FileHandle) string {
	return fmt.Sprintf("IRC DCC transfer on connection %s", handle.ConversationID)
}

// ExtractFile performs IRC DCC file extraction
func (i *IRCFileExtractor) ExtractFile(conv *core.ConversationInfo, data []byte, metadata file.FileMetadata) error {
	source := "IRC DCC SEND"

	filename := metadata.Filename
	if filename == "" {
		filename = "irc-dcc-file"
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
		"IRC", // protocol
	)
}

// ProtocolName returns the protocol name
func (i *IRCFileExtractor) ProtocolName() string {
	return "IRC"
}

// RegisterIRCExtractor registers the IRC file extractor
func init() {
	file.RegisterExtractor(&IRCFileExtractor{})
}
