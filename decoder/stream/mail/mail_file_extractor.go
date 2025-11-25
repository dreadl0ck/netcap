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

package mail

import (
	"fmt"

	"github.com/dreadl0ck/netcap/decoder/core"
	"github.com/dreadl0ck/netcap/decoder/stream/file"
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
	if !file.IsProtocolEnabled("SMTP") {
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
		nil, // no error
		data,
		metadata.Encoding,
		metadata.Host,
		metadata.ContentType,
		0,  // depth
		"", // parent file ID - could link to the email message
		metadata.FlowDirection,
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
