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

	"github.com/dreadl0ck/netcap/decoder"
	"github.com/dreadl0ck/netcap/decoder/core"
	"github.com/dreadl0ck/netcap/reassembly"
	"github.com/dreadl0ck/netcap/types"
	"go.uber.org/zap"
)

// DataDecoder for FTP DATA channel analysis
// This decoder tries to detect FTP data connections by checking against tracked connections
var DataDecoder = &decoder.StreamDecoder{
	Type:        types.Type_NC_FTP,
	Name:        "FTP-DATA",
	Description: "File Transfer Protocol - data channel",
	PostInit: func(sd *decoder.StreamDecoder) error {
		// Share the same logger as control channel
		return nil
	},
	CanDecode: func(client, server []byte) bool {
		// FTP DATA channel is just raw data, no protocol markers
		// We'll use connection tracking to identify these
		// For now, return false - actual detection happens via CheckDataConnection
		return false
	},
	DeInit: func(sd *decoder.StreamDecoder) error {
		return nil
	},
	Factory: &ftpDataReader{},
	Typ:     core.TCP,
}

// ftpDataReader handles FTP DATA channel content
type ftpDataReader struct {
	conversation *core.ConversationInfo
}

// New creates a new FTP data channel decoder
func (f *ftpDataReader) New(conversation *core.ConversationInfo) core.StreamDecoderInterface {
	return &ftpDataReader{
		conversation: conversation,
	}
}

// Decode extracts file data from FTP DATA channel
func (f *ftpDataReader) Decode() {
	// Check if this connection matches a tracked data connection
	keys := []string{
		fmt.Sprintf("%s:%d", f.conversation.ServerIP, f.conversation.ServerPort),
		fmt.Sprintf("%s:%d", f.conversation.ClientIP, f.conversation.ClientPort),
	}

	var connInfo *FTPDataConnection
	var found bool
	var matchedKey string

	for _, key := range keys {
		connInfo, found = CheckDataConnection(key)
		if found {
			matchedKey = key
			break
		}
	}

	if !found {
		// Not a tracked FTP data connection
		return
	}

	ftpLog.Info("Processing FTP DATA channel",
		zap.String("filename", connInfo.Filename),
		zap.String("command", connInfo.Command),
		zap.Int("serverPort", int(f.conversation.ServerPort)),
		zap.String("ident", f.conversation.Ident),
	)

	// Get the actual file data based on transfer direction
	// For RETR (download), data comes from server
	// For STOR (upload), data comes from client
	var fileData []byte

	// Extract data from the appropriate direction using Direction()
	for _, fragment := range f.conversation.Data {
		dir := fragment.Direction()

		if connInfo.Command == "STOR" {
			// Upload: client to server
			if dir == reassembly.TCPDirClientToServer {
				fileData = append(fileData, fragment.Raw()...)
			}
		} else {
			// Download (RETR) or default: server to client
			if dir == reassembly.TCPDirServerToClient {
				fileData = append(fileData, fragment.Raw()...)
			}
		}
	}

	if len(fileData) == 0 {
		ftpLog.Warn("No data in FTP DATA channel",
			zap.String("command", connInfo.Command),
			zap.String("ident", f.conversation.Ident),
		)
		RemoveDataConnection(matchedKey)
		return
	}

	// Extract file
	err := ExtractDataChannel(f.conversation, fileData, connInfo)
	if err != nil {
		ftpLog.Error("Failed to extract FTP file",
			zap.Error(err),
			zap.String("ident", f.conversation.Ident),
		)
	}

	// Clean up tracking entry after successful extraction
	RemoveDataConnection(matchedKey)
}

// ShouldDecodeAsDataChannel checks if a conversation should be decoded as FTP DATA
// This is called during stream identification
func ShouldDecodeAsDataChannel(conv *core.ConversationInfo) bool {
	keys := []string{
		fmt.Sprintf("%s:%d", conv.ServerIP, conv.ServerPort),
		fmt.Sprintf("%s:%d", conv.ClientIP, conv.ClientPort),
	}

	for _, key := range keys {
		if _, ok := CheckDataConnection(key); ok {
			ftpLog.Debug("Identified FTP DATA channel",
				zap.String("key", key),
				zap.String("ident", conv.Ident),
			)
			return true
		}
	}

	return false
}

// RemoveDataConnection removes a tracked data connection
func RemoveDataConnection(key string) {
	ftpDataConnectionsMu.Lock()
	delete(ftpDataConnections, key)
	ftpDataConnectionsMu.Unlock()

	ftpLog.Debug("Removed FTP data connection tracking",
		zap.String("key", key),
	)
}
