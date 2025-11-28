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
	"bufio"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/core"
	"github.com/dreadl0ck/netcap/decoder/stream/file"
	streamutils "github.com/dreadl0ck/netcap/decoder/stream/utils"
	decoderutils "github.com/dreadl0ck/netcap/decoder/utils"
	"github.com/dreadl0ck/netcap/types"
	"go.uber.org/zap"
)

// FTP connection tracking for correlating control and data channels
var (
	ftpDataConnections   = make(map[string]*FTPDataConnection)
	ftpDataConnectionsMu sync.RWMutex
)

// FTPDataConnection tracks expected FTP data connections
type FTPDataConnection struct {
	IP           string
	Port         int
	Filename     string
	Command      string // RETR or STOR
	TransferMode string
	IsPassive    bool
	FileSize     int64
	CreatedAt    time.Time
}

func initConnectionTracker() {
	// Initialize or reset connection tracker
	ftpDataConnectionsMu.Lock()
	ftpDataConnections = make(map[string]*FTPDataConnection)
	ftpDataConnectionsMu.Unlock()

	// Start cleanup timer
	startCleanupTimer()
}

func startCleanupTimer() {
	// Start periodic cleanup of expired connections
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		for range ticker.C {
			CleanupExpiredConnections()
		}
	}()
}

// CleanupExpiredConnections removes stale data connection expectations
func CleanupExpiredConnections() {
	ftpDataConnectionsMu.Lock()
	defer ftpDataConnectionsMu.Unlock()

	now := time.Now()
	for key, conn := range ftpDataConnections {
		// Remove connections older than 5 minutes
		if now.Sub(conn.CreatedAt) > 5*time.Minute {
			delete(ftpDataConnections, key)
			ftpLog.Debug("Cleaned up expired FTP data connection tracking",
				zap.String("key", key),
			)
		}
	}
}

// ftpReader implements the stream decoder interface for FTP
type ftpReader struct {
	conversation *core.ConversationInfo
	lastCommand  string
	lastFilename string
	lastArg      string
	username     string
	transferMode string
	dataIP       string
	dataPort     int
	isPassive    bool
	fileSize     int64
}

// New creates a new FTP stream decoder
func (f *ftpReader) New(conversation *core.ConversationInfo) core.StreamDecoderInterface {
	return &ftpReader{
		conversation: conversation,
	}
}

// Decode parses the FTP control channel conversation
func (f *ftpReader) Decode() {
	streamutils.DecodeConversation(
		f.conversation.Ident,
		f.conversation.Data,
		func(b *bufio.Reader) error {
			return f.readClient(b)
		},
		func(b *bufio.Reader) error {
			return f.readServer(b)
		},
	)
}

// readClient parses FTP commands from client
func (f *ftpReader) readClient(b *bufio.Reader) error {
	line, err := b.ReadString('\n')
	if err != nil {
		return err
	}

	line = strings.TrimSpace(line)
	parts := strings.SplitN(line, " ", 2)

	if len(parts) == 0 {
		return nil
	}

	command := strings.ToUpper(parts[0])
	argument := ""
	if len(parts) > 1 {
		argument = strings.TrimSpace(parts[1])
	}

	f.lastCommand = command
	f.lastArg = argument

	// Write FTP audit record for command
	f.writeFTPRecord(false, command, argument, 0, "")

	// Handle specific commands
	switch command {
	case "USER":
		f.username = argument

	case "RETR", "STOR":
		f.lastFilename = argument
		ftpLog.Debug("FTP file transfer command",
			zap.String("command", command),
			zap.String("filename", f.lastFilename),
			zap.String("ident", f.conversation.Ident),
		)

	case "TYPE":
		// Transfer mode: A (ASCII), I (IMAGE/Binary), E (EBCDIC)
		if argument == "A" {
			f.transferMode = "ASCII"
		} else if argument == "I" {
			f.transferMode = "BINARY"
		} else if argument == "E" {
			f.transferMode = "EBCDIC"
		}

	case "PORT":
		// Active mode: PORT h1,h2,h3,h4,p1,p2
		f.parsePORTCommand(argument)

	case "SIZE":
		// Client requesting file size (useful for tracking)
		f.lastFilename = argument
	}

	return nil
}

// parsePORTCommand parses the PORT command for active mode data connection
// Format: PORT h1,h2,h3,h4,p1,p2 where IP=h1.h2.h3.h4 and port=p1*256+p2
func (f *ftpReader) parsePORTCommand(arg string) {
	parts := strings.Split(arg, ",")
	if len(parts) != 6 {
		return
	}

	// Parse IP address
	f.dataIP = fmt.Sprintf("%s.%s.%s.%s", parts[0], parts[1], parts[2], parts[3])

	// Parse port
	p1, err1 := strconv.Atoi(parts[4])
	p2, err2 := strconv.Atoi(parts[5])
	if err1 == nil && err2 == nil {
		f.dataPort = (p1 * 256) + p2
		f.isPassive = false

		// Track this data connection
		f.trackDataConnection()

		ftpLog.Debug("FTP PORT command",
			zap.String("dataIP", f.dataIP),
			zap.Int("dataPort", f.dataPort),
			zap.String("ident", f.conversation.Ident),
		)
	}
}

// parsePASVResponse parses PASV response for passive mode
// Format: 227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)
var pasvRegex = regexp.MustCompile(`\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)`)

func (f *ftpReader) parsePASVResponse(message string) {
	matches := pasvRegex.FindStringSubmatch(message)
	if len(matches) != 7 {
		return
	}

	// Parse IP and port
	f.dataIP = fmt.Sprintf("%s.%s.%s.%s", matches[1], matches[2], matches[3], matches[4])

	p1, err1 := strconv.Atoi(matches[5])
	p2, err2 := strconv.Atoi(matches[6])
	if err1 == nil && err2 == nil {
		f.dataPort = (p1 * 256) + p2
		f.isPassive = true

		// Track this data connection
		f.trackDataConnection()

		ftpLog.Debug("FTP PASV response",
			zap.String("dataIP", f.dataIP),
			zap.Int("dataPort", f.dataPort),
			zap.String("ident", f.conversation.Ident),
		)
	}
}

// trackDataConnection records the expected data connection
func (f *ftpReader) trackDataConnection() {
	if f.dataIP == "" || f.dataPort == 0 {
		return
	}

	key := fmt.Sprintf("%s:%d", f.dataIP, f.dataPort)

	ftpDataConnectionsMu.Lock()
	ftpDataConnections[key] = &FTPDataConnection{
		IP:           f.dataIP,
		Port:         f.dataPort,
		Filename:     f.lastFilename,
		Command:      f.lastCommand,
		TransferMode: f.transferMode,
		IsPassive:    f.isPassive,
		FileSize:     f.fileSize,
		CreatedAt:    time.Now(),
	}
	ftpDataConnectionsMu.Unlock()

	ftpLog.Info("Tracked FTP data connection",
		zap.String("key", key),
		zap.String("filename", f.lastFilename),
		zap.String("command", f.lastCommand),
	)
}

// readServer parses FTP responses from server
func (f *ftpReader) readServer(b *bufio.Reader) error {
	line, err := b.ReadString('\n')
	if err != nil {
		return err
	}

	line = strings.TrimSpace(line)

	// FTP responses are typically "### message"
	if len(line) < 3 {
		return nil
	}

	// Parse response code
	codeStr := line[:3]
	code, err := strconv.Atoi(codeStr)
	if err != nil {
		return nil
	}

	message := ""
	if len(line) > 4 {
		message = line[4:]
	}

	// Write FTP audit record for response
	f.writeFTPRecord(true, "", "", int32(code), message)

	// Handle specific responses
	switch code {
	case 150:
		// Data transfer starting
		ftpLog.Debug("FTP data transfer started",
			zap.String("lastCommand", f.lastCommand),
			zap.String("filename", f.lastFilename),
			zap.String("ident", f.conversation.Ident),
		)

	case 213:
		// SIZE response: 213 <size>
		if size, err := strconv.ParseInt(message, 10, 64); err == nil {
			f.fileSize = size
		}

	case 227:
		// PASV response
		f.parsePASVResponse(message)
	}

	return nil
}

// extractFile attempts to extract a file from FTP DATA channel
// Note: This is a simplified implementation. Full FTP DATA channel tracking
// requires correlating control and data connections, which needs more infrastructure.
func (f *ftpReader) extractFile(data []byte) error {
	if decoderconfig.Instance.FileStorage == "" {
		return nil
	}

	if len(data) == 0 {
		return nil
	}

	filename := f.lastFilename
	if filename == "" {
		filename = "ftp-file"
	}
	filename = filepath.Base(filename)

	// Determine flow direction based on command
	flowDirection := "server_to_client" // RETR (download)
	if f.lastCommand == "STOR" {
		flowDirection = "client_to_server" // STOR (upload)
	}

	// Use file extraction framework
	if extractor, ok := file.GetExtractor("FTP"); ok {
		metadata := file.FileMetadata{
			ConnectionUID: f.conversation.Ident,
			FlowDirection: flowDirection,
			FTPCommand:    f.lastCommand,
			Filename:      filename,
			Host:          f.conversation.ServerIP,
		}
		return extractor.ExtractFile(f.conversation, data, metadata)
	}

	return nil
}

// writeFTPRecord writes an FTP audit record
func (f *ftpReader) writeFTPRecord(isResponse bool, command, argument string, responseCode int32, responseMessage string) {
	if Decoder.Writer == nil {
		return
	}

	dataMode := "UNKNOWN"
	if f.isPassive {
		dataMode = "PASSIVE"
	} else if f.dataIP != "" {
		dataMode = "ACTIVE"
	}

	ftp := &types.FTP{
		Timestamp:          f.conversation.FirstClientPacket.UnixNano(),
		SrcIP:              f.conversation.ClientIP,
		DstIP:              f.conversation.ServerIP,
		SrcPort:            f.conversation.ClientPort,
		DstPort:            f.conversation.ServerPort,
		IsResponse:         isResponse,
		Command:            command,
		Argument:           argument,
		ResponseCode:       responseCode,
		ResponseMessage:    responseMessage,
		Filename:           f.lastFilename,
		TransferMode:       f.transferMode,
		DataConnectionMode: dataMode,
		DataIP:             f.dataIP,
		DataPort:           int32(f.dataPort),
		Username:           f.username,
		IsControl:          true,
		FileSize:           f.fileSize,
	}

	atomic.AddInt64(&Decoder.NumRecordsWritten, 1)
	err := Decoder.Writer.Write(ftp)
	if err != nil {
		decoderutils.ErrorMap.Inc(err.Error())
	}
}

// CheckDataConnection checks if a connection matches an expected FTP data connection
func CheckDataConnection(key string) (*FTPDataConnection, bool) {
	ftpDataConnectionsMu.RLock()
	conn, ok := ftpDataConnections[key]
	ftpDataConnectionsMu.RUnlock()

	return conn, ok
}

// ExtractDataChannel extracts file from FTP data channel
func ExtractDataChannel(conv *core.ConversationInfo, data []byte, conn *FTPDataConnection) error {
	if len(data) == 0 {
		return nil
	}

	ftpLog.Info("Extracting FTP data channel file",
		zap.String("filename", conn.Filename),
		zap.String("command", conn.Command),
		zap.Int("dataSize", len(data)),
		zap.String("ident", conv.Ident),
	)

	// Use file extraction framework
	extractor, ok := file.GetExtractor("FTP")
	if !ok {
		ftpLog.Error("FTP file extractor not registered")
		return nil
	}

	flowDirection := "server_to_client"
	if conn.Command == "STOR" {
		flowDirection = "client_to_server"
	}

	metadata := file.FileMetadata{
		ConnectionUID: conv.Ident,
		FlowDirection: flowDirection,
		FTPCommand:    conn.Command,
		Filename:      filepath.Base(conn.Filename),
		Host:          conn.IP,
	}

	return extractor.ExtractFile(conv, data, metadata)
}
