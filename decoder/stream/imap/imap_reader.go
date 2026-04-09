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

package imap

import (
	"bufio"
	"strings"
	"sync/atomic"

	"github.com/dreadl0ck/netcap/decoder/core"
	streamutils "github.com/dreadl0ck/netcap/decoder/stream/utils"
	decoderutils "github.com/dreadl0ck/netcap/decoder/utils"
	"github.com/dreadl0ck/netcap/types"
	"go.uber.org/zap"
)

// imapReader implements the stream decoder interface for IMAP
type imapReader struct {
	conversation    *core.ConversationInfo
	currentMailbox  string
	username        string
	authMethod      string
	startTLSReq     bool
	startTLSSuccess bool
	isEncrypted     bool
	capabilities    []string
	messageCount    int32
	recentCount     int32
}

// New creates a new IMAP stream decoder
func (i *imapReader) New(conversation *core.ConversationInfo) core.StreamDecoderInterface {
	return &imapReader{
		conversation: conversation,
	}
}

// Decode parses the IMAP conversation
func (i *imapReader) Decode() {
	streamutils.DecodeConversation(
		i.conversation.Ident,
		i.conversation.Data,
		func(b *bufio.Reader) error {
			return i.readClient(b)
		},
		func(b *bufio.Reader) error {
			return i.readServer(b)
		},
	)
}

// readClient parses IMAP commands from client
func (i *imapReader) readClient(b *bufio.Reader) error {
	line, err := b.ReadString('\n')
	if err != nil {
		return err
	}

	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}

	// Parse IMAP command format: TAG COMMAND [arguments]
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return nil
	}

	tag := parts[0]
	command := strings.ToUpper(parts[1])
	arguments := parts[2:]

	imapLog.Debug("IMAP command",
		zap.String("tag", tag),
		zap.String("command", command),
		zap.Strings("args", arguments),
		zap.String("ident", i.conversation.Ident),
	)

	// Handle specific commands
	switch command {
	case "LOGIN":
		// LOGIN command: tag LOGIN username password
		if len(arguments) >= 1 {
			i.username = strings.Trim(arguments[0], "\"")
			i.authMethod = "LOGIN"
		}

	case "AUTHENTICATE":
		// AUTHENTICATE command: tag AUTHENTICATE mechanism
		if len(arguments) >= 1 {
			i.authMethod = arguments[0]
		}

	case "SELECT", "EXAMINE":
		// SELECT/EXAMINE: tag SELECT mailbox
		if len(arguments) >= 1 {
			i.currentMailbox = strings.Trim(arguments[0], "\"")
		}

	case "STARTTLS":
		i.startTLSReq = true
		imapLog.Info("IMAP STARTTLS requested",
			zap.String("ident", i.conversation.Ident),
		)
	}

	// Write IMAP audit record
	i.writeIMAPRecord(false, tag, command, arguments, "", "")

	return nil
}

// readServer parses IMAP responses from server
func (i *imapReader) readServer(b *bufio.Reader) error {
	line, err := b.ReadString('\n')
	if err != nil {
		return err
	}

	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}

	// IMAP responses can be:
	// - Untagged: * OK, * CAPABILITY, * LIST, etc.
	// - Tagged: A001 OK, A002 NO, etc.

	parts := strings.Fields(line)
	if len(parts) < 2 {
		return nil
	}

	var tag, response, responseText string

	if parts[0] == "*" {
		// Untagged response
		tag = "*"
		response = parts[1]
		if len(parts) > 2 {
			responseText = strings.Join(parts[2:], " ")
		}

		// Parse untagged responses
		switch response {
		case "CAPABILITY":
			i.capabilities = parts[2:]
			imapLog.Debug("IMAP capabilities",
				zap.Strings("caps", i.capabilities),
				zap.String("ident", i.conversation.Ident),
			)

		case "OK":
			// Check for STARTTLS success
			if i.startTLSReq && strings.Contains(line, "STARTTLS") {
				i.startTLSSuccess = true
				i.isEncrypted = true
				imapLog.Info("IMAP STARTTLS successful",
					zap.String("ident", i.conversation.Ident),
				)
			}
		}

	} else {
		// Tagged response
		tag = parts[0]
		if len(parts) > 1 {
			response = parts[1]
		}
		if len(parts) > 2 {
			responseText = strings.Join(parts[2:], " ")
		}
	}

	imapLog.Debug("IMAP response",
		zap.String("tag", tag),
		zap.String("response", response),
		zap.String("text", responseText),
		zap.String("ident", i.conversation.Ident),
	)

	// Write IMAP audit record
	i.writeIMAPRecord(true, tag, "", nil, response, responseText)

	return nil
}

// writeIMAPRecord writes an IMAP audit record
func (i *imapReader) writeIMAPRecord(isResponse bool, tag, command string, arguments []string, response, responseText string) {
	if Decoder.Writer == nil {
		return
	}

	imap := &types.IMAP{
		Timestamp:         i.conversation.FirstClientPacket.UnixNano(),
		SrcIP:             i.conversation.ClientIP,
		DstIP:             i.conversation.ServerIP,
		SrcPort:           i.conversation.ClientPort,
		DstPort:           i.conversation.ServerPort,
		IsResponse:        isResponse,
		Tag:               tag,
		Command:           command,
		Arguments:         arguments,
		Response:          response,
		ResponseText:      responseText,
		Username:          i.username,
		AuthMethod:        i.authMethod,
		Mailbox:           i.currentMailbox,
		STARTTLSRequested: i.startTLSReq,
		STARTTLSSuccess:   i.startTLSSuccess,
		IsEncrypted:       i.isEncrypted,
		Capabilities:      i.capabilities,
		CommunityID:       i.conversation.CommunityID,
	}

	atomic.AddInt64(&Decoder.NumRecordsWritten, 1)
	err := Decoder.Writer.Write(imap)
	if err != nil {
		decoderutils.ErrorMap.Inc(err.Error())
	}
}
