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
		0, // depth
		"", // parent file ID
		metadata.FlowDirection,
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

