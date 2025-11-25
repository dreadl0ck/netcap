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
	"bufio"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dreadl0ck/netcap/decoder/core"
	streamutils "github.com/dreadl0ck/netcap/decoder/stream/utils"
	decoderutils "github.com/dreadl0ck/netcap/decoder/utils"
	"github.com/dreadl0ck/netcap/types"
	"go.uber.org/zap"
)

// IRC DCC connection tracking
var (
	ircDCCConnections   = make(map[string]*IRCDCCConnection)
	ircDCCConnectionsMu sync.RWMutex
)

// IRCDCCConnection tracks expected IRC DCC data connections
type IRCDCCConnection struct {
	IP        string
	Port      int
	Filename  string
	Filesize  int64
	Type      string // SEND, CHAT, etc.
	Nick      string
	CreatedAt time.Time
}

func initIRCConnectionTracker() {
	ircDCCConnectionsMu.Lock()
	ircDCCConnections = make(map[string]*IRCDCCConnection)
	ircDCCConnectionsMu.Unlock()
	
	// Start cleanup timer
	go func() {
		ticker := time.NewTicker(2 * time.Minute)
		for range ticker.C {
			cleanupExpiredDCCConnectionsInternal()
		}
	}()
}

// cleanupExpiredDCCConnectionsInternal is the internal cleanup function
func cleanupExpiredDCCConnectionsInternal() {
	ircDCCConnectionsMu.Lock()
	defer ircDCCConnectionsMu.Unlock()

	now := time.Now()
	for key, conn := range ircDCCConnections {
		if now.Sub(conn.CreatedAt) > 10*time.Minute {
			delete(ircDCCConnections, key)
			ircLog.Debug("Cleaned up expired IRC DCC connection tracking",
				zap.String("key", key),
			)
		}
	}
}

// ircReader implements the stream decoder interface for IRC
type ircReader struct {
	conversation *core.ConversationInfo
	dccFilename  string
	dccFilesize  int64
	dccIP        string
	dccPort      int
	dccType      string
	currentNick  string
	currentChan  string
}

// New creates a new IRC stream decoder
func (i *ircReader) New(conversation *core.ConversationInfo) core.StreamDecoderInterface {
	return &ircReader{
		conversation: conversation,
	}
}

// Decode parses the IRC conversation
func (i *ircReader) Decode() {
	streamutils.DecodeConversation(
		i.conversation.Ident,
		i.conversation.Data,
		func(b *bufio.Reader) error {
			return i.readMessage(b, true)
		},
		func(b *bufio.Reader) error {
			return i.readMessage(b, false)
		},
	)
}

// readMessage parses IRC messages (both client and server)
func (i *ircReader) readMessage(b *bufio.Reader, isClient bool) error {
	line, err := b.ReadString('\n')
	if err != nil {
		return err
	}

	line = strings.TrimSpace(line)
	
	// Parse IRC message format: [prefix] command [parameters]
	prefix, command, params := i.parseIRCMessage(line)
	
	// Write IRC audit record
	i.writeIRCRecord(prefix, command, params, line)
	
	// Handle specific commands
	switch strings.ToUpper(command) {
	case "NICK":
		if len(params) > 0 {
			i.currentNick = params[0]
		}
	case "JOIN":
		if len(params) > 0 {
			i.currentChan = params[0]
		}
	case "PRIVMSG":
		// Check for DCC commands in PRIVMSG
		if len(params) > 1 {
			message := params[1]
			if strings.Contains(message, "DCC") {
				i.parseDCCCommand(message)
			}
		}
	}

	return nil
}

// parseIRCMessage parses an IRC protocol message
// Format: [:prefix] COMMAND [param1 param2 ... :trailing param]
func (i *ircReader) parseIRCMessage(line string) (prefix, command string, params []string) {
	// Remove CTCP markers
	line = strings.Trim(line, "\x01")
	
	// Check for prefix
	if strings.HasPrefix(line, ":") {
		parts := strings.SplitN(line[1:], " ", 2)
		if len(parts) >= 2 {
			prefix = parts[0]
			line = parts[1]
		}
	}
	
	// Parse command and parameters
	parts := strings.Split(line, " ")
	if len(parts) > 0 {
		command = parts[0]
		
		// Parse parameters
		for i := 1; i < len(parts); i++ {
			if strings.HasPrefix(parts[i], ":") {
				// Rest of line is trailing parameter
				params = append(params, strings.Join(parts[i:], " ")[1:])
				break
			}
			params = append(params, parts[i])
		}
	}
	
	return prefix, command, params
}

// parseDCCCommand extracts DCC parameters from CTCP message
func (i *ircReader) parseDCCCommand(message string) {
	// Example: \x01DCC SEND file.zip 3232235777 6666 102400\x01
	
	// Remove CTCP markers
	message = strings.Trim(message, "\x01")
	
	parts := strings.Fields(message)
	if len(parts) < 3 || parts[0] != "DCC" {
		return
	}

	i.dccType = parts[1]
	
	switch i.dccType {
	case "SEND":
		if len(parts) >= 6 {
			i.dccFilename = parts[2]
			
			// Parse IP (usually as decimal number)
			if ipNum, err := strconv.ParseInt(parts[3], 10, 64); err == nil {
				i.dccIP = fmt.Sprintf("%d.%d.%d.%d",
					(ipNum>>24)&0xFF,
					(ipNum>>16)&0xFF,
					(ipNum>>8)&0xFF,
					ipNum&0xFF)
			}
			
			// Parse port
			if port, err := strconv.Atoi(parts[4]); err == nil {
				i.dccPort = port
			}
			
			// Parse filesize
			if size, err := strconv.ParseInt(parts[5], 10, 64); err == nil {
				i.dccFilesize = size
			}

			// Track this DCC connection
			i.trackDCCConnection()

			ircLog.Info("DCC SEND detected",
				zap.String("filename", i.dccFilename),
				zap.String("ip", i.dccIP),
				zap.Int("port", i.dccPort),
				zap.Int64("size", i.dccFilesize),
				zap.String("ident", i.conversation.Ident),
			)
		}
	}
}

// trackDCCConnection records the expected DCC data connection
func (i *ircReader) trackDCCConnection() {
	if i.dccIP == "" || i.dccPort == 0 {
		return
	}

	key := fmt.Sprintf("%s:%d", i.dccIP, i.dccPort)
	
	ircDCCConnectionsMu.Lock()
	ircDCCConnections[key] = &IRCDCCConnection{
		IP:        i.dccIP,
		Port:      i.dccPort,
		Filename:  i.dccFilename,
		Filesize:  i.dccFilesize,
		Type:      i.dccType,
		Nick:      i.currentNick,
		CreatedAt: time.Now(),
	}
	ircDCCConnectionsMu.Unlock()
	
	ircLog.Info("Tracked IRC DCC connection",
		zap.String("key", key),
		zap.String("filename", i.dccFilename),
		zap.String("type", i.dccType),
	)
}

// writeIRCRecord writes an IRC audit record
func (i *ircReader) writeIRCRecord(prefix, command string, params []string, rawLine string) {
	if Decoder.Writer == nil {
		return
	}

	// Extract message content for PRIVMSG
	message := ""
	if strings.ToUpper(command) == "PRIVMSG" && len(params) > 1 {
		message = params[1]
	}

	irc := &types.IRC{
		Timestamp:  i.conversation.FirstClientPacket.UnixNano(),
		SrcIP:      i.conversation.ClientIP,
		DstIP:      i.conversation.ServerIP,
		SrcPort:    i.conversation.ClientPort,
		DstPort:    i.conversation.ServerPort,
		Prefix:     prefix,
		Command:    command,
		Parameters: params,
		Message:    message,
		IsDCC:      i.dccType != "",
		DCCType:    i.dccType,
		DCCFilename: i.dccFilename,
		DCCIP:      i.dccIP,
		DCCPort:    int32(i.dccPort),
		DCCFilesize: i.dccFilesize,
		Channel:    i.currentChan,
		Nick:       i.currentNick,
		IsDataChannel: false,
	}

	atomic.AddInt64(&Decoder.NumRecordsWritten, 1)
	err := Decoder.Writer.Write(irc)
	if err != nil {
		decoderutils.ErrorMap.Inc(err.Error())
	}
}

// CheckDCCConnection checks if a connection matches an expected IRC DCC connection
func CheckDCCConnection(key string) (*IRCDCCConnection, bool) {
	ircDCCConnectionsMu.RLock()
	conn, ok := ircDCCConnections[key]
	ircDCCConnectionsMu.RUnlock()
	
	return conn, ok
}


