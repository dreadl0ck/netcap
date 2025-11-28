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
	"time"

	"github.com/dreadl0ck/netcap/decoder"
	"github.com/dreadl0ck/netcap/decoder/core"
	"github.com/dreadl0ck/netcap/decoder/stream/file"
	"github.com/dreadl0ck/netcap/types"
	"go.uber.org/zap"
)

// DataDecoder for IRC DCC data channel analysis
var DataDecoder = &decoder.StreamDecoder{
	Type:        types.Type_NC_IRC,
	Name:        "IRC-DCC",
	Description: "IRC DCC file transfer data channel",
	PostInit: func(sd *decoder.StreamDecoder) error {
		return nil
	},
	CanDecode: func(client, server []byte) bool {
		// DCC DATA channel is raw binary, no markers
		// Detection via connection tracking
		return false
	},
	DeInit: func(sd *decoder.StreamDecoder) error {
		return nil
	},
	Factory: &ircDCCDataReader{},
	Typ:     core.TCP,
}

// ircDCCDataReader handles IRC DCC data channel
type ircDCCDataReader struct {
	conversation *core.ConversationInfo
}

// New creates a new IRC DCC data reader
func (i *ircDCCDataReader) New(conversation *core.ConversationInfo) core.StreamDecoderInterface {
	return &ircDCCDataReader{
		conversation: conversation,
	}
}

// Decode extracts file from IRC DCC DATA channel
func (i *ircDCCDataReader) Decode() {
	// Check if this connection matches a tracked DCC connection
	keys := []string{
		fmt.Sprintf("%s:%d", i.conversation.ServerIP, i.conversation.ServerPort),
		fmt.Sprintf("%s:%d", i.conversation.ClientIP, i.conversation.ClientPort),
	}

	var connInfo *IRCDCCConnection
	var found bool
	var matchedKey string

	for _, key := range keys {
		connInfo, found = CheckDCCConnection(key)
		if found {
			matchedKey = key
			break
		}
	}

	if !found {
		// Not a tracked DCC connection
		return
	}

	ircLog.Info("Processing IRC DCC DATA channel",
		zap.String("filename", connInfo.Filename),
		zap.String("type", connInfo.Type),
		zap.Int64("expectedSize", connInfo.Filesize),
		zap.String("ident", i.conversation.Ident),
	)

	// DCC SEND: sender connects to receiver
	// Data flows from sender (collect all data, typically from one direction)
	var fileData []byte

	// Extract all data from the connection
	// DCC transfers are typically unidirectional
	for _, fragment := range i.conversation.Data {
		fileData = append(fileData, fragment.Raw()...)
	}

	if len(fileData) == 0 {
		ircLog.Warn("No data in IRC DCC channel",
			zap.String("ident", i.conversation.Ident),
		)
		RemoveDCCConnection(matchedKey)
		return
	}

	ircLog.Info("Extracting IRC DCC file",
		zap.String("filename", connInfo.Filename),
		zap.Int("dataSize", len(fileData)),
		zap.Int64("expectedSize", connInfo.Filesize),
		zap.String("ident", i.conversation.Ident),
	)

	// Extract file
	err := ExtractDCCDataChannel(i.conversation, fileData, connInfo)
	if err != nil {
		ircLog.Error("Failed to extract IRC DCC file",
			zap.Error(err),
			zap.String("ident", i.conversation.Ident),
		)
	}

	// Clean up tracking
	RemoveDCCConnection(matchedKey)
}

// ShouldDecodeAsDCCData checks if a conversation should be decoded as IRC DCC DATA
func ShouldDecodeAsDCCData(conv *core.ConversationInfo) bool {
	keys := []string{
		fmt.Sprintf("%s:%d", conv.ServerIP, conv.ServerPort),
		fmt.Sprintf("%s:%d", conv.ClientIP, conv.ClientPort),
	}

	for _, key := range keys {
		if _, ok := CheckDCCConnection(key); ok {
			ircLog.Debug("Identified IRC DCC DATA channel",
				zap.String("key", key),
				zap.String("ident", conv.Ident),
			)
			return true
		}
	}

	return false
}

// ExtractDCCDataChannel extracts file from IRC DCC data channel
func ExtractDCCDataChannel(conv *core.ConversationInfo, data []byte, conn *IRCDCCConnection) error {
	if len(data) == 0 {
		return nil
	}

	// Use file extraction framework
	extractor, ok := file.GetExtractor("IRC")
	if !ok {
		ircLog.Error("IRC file extractor not registered")
		return nil
	}

	metadata := file.FileMetadata{
		ConnectionUID: conv.Ident,
		FlowDirection: "server_to_client", // DCC SEND is typically download
		Filename:      filepath.Base(conn.Filename),
		Host:          conn.IP,
	}

	return extractor.ExtractFile(conv, data, metadata)
}

// RemoveDCCConnection removes a tracked DCC connection
func RemoveDCCConnection(key string) {
	ircDCCConnectionsMu.Lock()
	delete(ircDCCConnections, key)
	ircDCCConnectionsMu.Unlock()

	ircLog.Debug("Removed IRC DCC connection tracking",
		zap.String("key", key),
	)
}

// CleanupExpiredDCCConnections removes stale DCC connection expectations
func CleanupExpiredDCCConnections() {
	ircDCCConnectionsMu.Lock()
	defer ircDCCConnectionsMu.Unlock()

	now := time.Now()
	for key, conn := range ircDCCConnections {
		// Remove connections older than 10 minutes
		if now.Sub(conn.CreatedAt) > 10*time.Minute {
			delete(ircDCCConnections, key)
			ircLog.Debug("Cleaned up expired IRC DCC connection tracking",
				zap.String("key", key),
			)
		}
	}
}
