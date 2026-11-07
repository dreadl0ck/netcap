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

package mail

import (
	"fmt"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/file"
)

// MailFileExtractor implements file extraction for email attachments
type MailFileExtractor struct{}

// GetFileHandle generates a unique identifier for an email attachment
func (m *MailFileExtractor) GetFileHandle(conv *core.ConversationInfo, isOrigin bool, depth int) string {
	return fmt.Sprintf("MAIL-%s-%d-%v", conv.Ident, depth, isOrigin)
}

// DescribeFile returns a human-readable description of the email attachment
func (m *MailFileExtractor) DescribeFile(handle *file.FileHandle) string {
	return fmt.Sprintf("Email attachment on connection %s", handle.ConversationID)
}

// ExtractFile performs email attachment extraction
func (m *MailFileExtractor) ExtractFile(conv *core.ConversationInfo, data []byte, metadata file.FileMetadata) error {
	// Check if SMTP/email file extraction is enabled
	protocol := metadata.Protocol
	if protocol == "" {
		protocol = "SMTP"
	}
	if !file.IsProtocolEnabled(protocol) {
		return nil
	}

	source := "Email Attachment"
	if metadata.Host != "" {
		source = fmt.Sprintf("Email Attachment from %s", metadata.Host)
	}

	filename := metadata.Filename
	if filename == "" {
		filename = "attachment"
	}

	return file.SaveFileEnhanced(
		conv,
		source,
		filename,
		metadata.ExtractionError,
		data,
		metadata.Encoding,
		metadata.Host,
		metadata.ContentType,
		metadata.Depth,
		metadata.ParentFileID,
		metadata.FlowDirection,
		protocol,
	)
}

// ProtocolName returns the protocol name
func (m *MailFileExtractor) ProtocolName() string {
	return "MAIL"
}

// RegisterMailExtractor registers the mail file extractor
func init() {
	file.RegisterExtractor(&MailFileExtractor{})
}
