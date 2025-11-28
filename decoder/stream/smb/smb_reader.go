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

package smb

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
	"unicode/utf16"

	"github.com/dreadl0ck/netcap/decoder/core"
	streamutils "github.com/dreadl0ck/netcap/decoder/stream/utils"
	decoderutils "github.com/dreadl0ck/netcap/decoder/utils"
	"github.com/dreadl0ck/netcap/types"
	"go.uber.org/zap"
)

// SMB1 command codes
const (
	SMB1_COM_CREATE_DIRECTORY       = 0x00
	SMB1_COM_DELETE_DIRECTORY       = 0x01
	SMB1_COM_OPEN                   = 0x02
	SMB1_COM_CREATE                 = 0x03
	SMB1_COM_CLOSE                  = 0x04
	SMB1_COM_FLUSH                  = 0x05
	SMB1_COM_DELETE                 = 0x06
	SMB1_COM_RENAME                 = 0x07
	SMB1_COM_QUERY_INFORMATION      = 0x08
	SMB1_COM_SET_INFORMATION        = 0x09
	SMB1_COM_READ                   = 0x0A
	SMB1_COM_WRITE                  = 0x0B
	SMB1_COM_LOCK_BYTE_RANGE        = 0x0C
	SMB1_COM_UNLOCK_BYTE_RANGE      = 0x0D
	SMB1_COM_CREATE_TEMPORARY       = 0x0E
	SMB1_COM_CREATE_NEW             = 0x0F
	SMB1_COM_CHECK_DIRECTORY        = 0x10
	SMB1_COM_PROCESS_EXIT           = 0x11
	SMB1_COM_SEEK                   = 0x12
	SMB1_COM_LOCK_AND_READ          = 0x13
	SMB1_COM_WRITE_AND_UNLOCK       = 0x14
	SMB1_COM_READ_RAW               = 0x1A
	SMB1_COM_READ_MPX               = 0x1B
	SMB1_COM_READ_MPX_SECONDARY     = 0x1C
	SMB1_COM_WRITE_RAW              = 0x1D
	SMB1_COM_WRITE_MPX              = 0x1E
	SMB1_COM_WRITE_MPX_SECONDARY    = 0x1F
	SMB1_COM_WRITE_COMPLETE         = 0x20
	SMB1_COM_QUERY_SERVER           = 0x21
	SMB1_COM_SET_INFORMATION2       = 0x22
	SMB1_COM_QUERY_INFORMATION2     = 0x23
	SMB1_COM_LOCKING_ANDX           = 0x24
	SMB1_COM_TRANSACTION            = 0x25
	SMB1_COM_TRANSACTION_SECONDARY  = 0x26
	SMB1_COM_IOCTL                  = 0x27
	SMB1_COM_IOCTL_SECONDARY        = 0x28
	SMB1_COM_COPY                   = 0x29
	SMB1_COM_MOVE                   = 0x2A
	SMB1_COM_ECHO                   = 0x2B
	SMB1_COM_WRITE_AND_CLOSE        = 0x2C
	SMB1_COM_OPEN_ANDX              = 0x2D
	SMB1_COM_READ_ANDX              = 0x2E
	SMB1_COM_WRITE_ANDX             = 0x2F
	SMB1_COM_NEW_FILE_SIZE          = 0x30
	SMB1_COM_CLOSE_AND_TREE_DISC    = 0x31
	SMB1_COM_TRANSACTION2           = 0x32
	SMB1_COM_TRANSACTION2_SECONDARY = 0x33
	SMB1_COM_FIND_CLOSE2            = 0x34
	SMB1_COM_FIND_NOTIFY_CLOSE      = 0x35
	SMB1_COM_TREE_CONNECT           = 0x70
	SMB1_COM_TREE_DISCONNECT        = 0x71
	SMB1_COM_NEGOTIATE              = 0x72
	SMB1_COM_SESSION_SETUP_ANDX     = 0x73
	SMB1_COM_LOGOFF_ANDX            = 0x74
	SMB1_COM_TREE_CONNECT_ANDX      = 0x75
	SMB1_COM_SECURITY_PACKAGE_ANDX  = 0x7E
	SMB1_COM_QUERY_INFORMATION_DISK = 0x80
	SMB1_COM_SEARCH                 = 0x81
	SMB1_COM_FIND                   = 0x82
	SMB1_COM_FIND_UNIQUE            = 0x83
	SMB1_COM_FIND_CLOSE             = 0x84
	SMB1_COM_NT_TRANSACT            = 0xA0
	SMB1_COM_NT_TRANSACT_SECONDARY  = 0xA1
	SMB1_COM_NT_CREATE_ANDX         = 0xA2
	SMB1_COM_NT_CANCEL              = 0xA4
	SMB1_COM_NT_RENAME              = 0xA5
	SMB1_COM_OPEN_PRINT_FILE        = 0xC0
	SMB1_COM_WRITE_PRINT_FILE       = 0xC1
	SMB1_COM_CLOSE_PRINT_FILE       = 0xC2
	SMB1_COM_GET_PRINT_QUEUE        = 0xC3
	SMB1_COM_READ_BULK              = 0xD8
	SMB1_COM_WRITE_BULK             = 0xD9
	SMB1_COM_WRITE_BULK_DATA        = 0xDA
)

// SMB2 command codes
const (
	SMB2_NEGOTIATE       = 0x0000
	SMB2_SESSION_SETUP   = 0x0001
	SMB2_LOGOFF          = 0x0002
	SMB2_TREE_CONNECT    = 0x0003
	SMB2_TREE_DISCONNECT = 0x0004
	SMB2_CREATE          = 0x0005
	SMB2_CLOSE           = 0x0006
	SMB2_FLUSH           = 0x0007
	SMB2_READ            = 0x0008
	SMB2_WRITE           = 0x0009
	SMB2_LOCK            = 0x000A
	SMB2_IOCTL           = 0x000B
	SMB2_CANCEL          = 0x000C
	SMB2_ECHO            = 0x000D
	SMB2_QUERY_DIRECTORY = 0x000E
	SMB2_CHANGE_NOTIFY   = 0x000F
	SMB2_QUERY_INFO      = 0x0010
	SMB2_SET_INFO        = 0x0011
	SMB2_OPLOCK_BREAK    = 0x0012
)

// SMB2 flags
const (
	SMB2_FLAGS_SERVER_TO_REDIR    = 0x00000001 // Response flag
	SMB2_FLAGS_ASYNC_COMMAND      = 0x00000002
	SMB2_FLAGS_RELATED_OPERATIONS = 0x00000004
	SMB2_FLAGS_SIGNED             = 0x00000008
	SMB2_FLAGS_PRIORITY_MASK      = 0x00000070
	SMB2_FLAGS_DFS_OPERATIONS     = 0x10000000
	SMB2_FLAGS_REPLAY_OPERATION   = 0x20000000
)

// Common NT Status codes for security monitoring
var ntStatusNames = map[uint32]string{
	0x00000000: "STATUS_SUCCESS",
	0x00000103: "STATUS_PENDING",
	0x80000005: "STATUS_BUFFER_OVERFLOW",
	0x80000006: "STATUS_NO_MORE_FILES",
	0x8000002D: "STATUS_STOPPED_ON_SYMLINK",
	0xC0000001: "STATUS_UNSUCCESSFUL",
	0xC0000002: "STATUS_NOT_IMPLEMENTED",
	0xC0000003: "STATUS_INVALID_INFO_CLASS",
	0xC0000004: "STATUS_INFO_LENGTH_MISMATCH",
	0xC0000005: "STATUS_ACCESS_VIOLATION",
	0xC0000006: "STATUS_IN_PAGE_ERROR",
	0xC0000008: "STATUS_INVALID_HANDLE",
	0xC000000D: "STATUS_INVALID_PARAMETER",
	0xC000000E: "STATUS_NO_SUCH_DEVICE",
	0xC000000F: "STATUS_NO_SUCH_FILE",
	0xC0000010: "STATUS_INVALID_DEVICE_REQUEST",
	0xC0000011: "STATUS_END_OF_FILE",
	0xC0000012: "STATUS_WRONG_VOLUME",
	0xC0000013: "STATUS_NO_MEDIA_IN_DEVICE",
	0xC0000016: "STATUS_MORE_PROCESSING_REQUIRED",
	0xC0000017: "STATUS_NO_MEMORY",
	0xC0000022: "STATUS_ACCESS_DENIED",
	0xC0000023: "STATUS_BUFFER_TOO_SMALL",
	0xC0000024: "STATUS_OBJECT_TYPE_MISMATCH",
	0xC0000033: "STATUS_OBJECT_NAME_INVALID",
	0xC0000034: "STATUS_OBJECT_NAME_NOT_FOUND",
	0xC0000035: "STATUS_OBJECT_NAME_COLLISION",
	0xC0000039: "STATUS_OBJECT_PATH_INVALID",
	0xC000003A: "STATUS_OBJECT_PATH_NOT_FOUND",
	0xC000003B: "STATUS_OBJECT_PATH_SYNTAX_BAD",
	0xC000003C: "STATUS_DATA_OVERRUN",
	0xC0000043: "STATUS_SHARING_VIOLATION",
	0xC0000044: "STATUS_QUOTA_EXCEEDED",
	0xC000004F: "STATUS_EAS_NOT_SUPPORTED",
	0xC0000050: "STATUS_EA_TOO_LARGE",
	0xC0000051: "STATUS_NONEXISTENT_EA_ENTRY",
	0xC0000052: "STATUS_NO_EAS_ON_FILE",
	0xC0000053: "STATUS_EA_CORRUPT_ERROR",
	0xC0000054: "STATUS_FILE_LOCK_CONFLICT",
	0xC0000055: "STATUS_LOCK_NOT_GRANTED",
	0xC0000056: "STATUS_DELETE_PENDING",
	0xC0000061: "STATUS_PRIVILEGE_NOT_HELD",
	0xC000006A: "STATUS_WRONG_PASSWORD",
	0xC000006C: "STATUS_PASSWORD_RESTRICTION",
	0xC000006D: "STATUS_LOGON_FAILURE",
	0xC000006E: "STATUS_ACCOUNT_RESTRICTION",
	0xC000006F: "STATUS_INVALID_LOGON_HOURS",
	0xC0000070: "STATUS_INVALID_WORKSTATION",
	0xC0000071: "STATUS_PASSWORD_EXPIRED",
	0xC0000072: "STATUS_ACCOUNT_DISABLED",
	0xC00000BA: "STATUS_FILE_IS_A_DIRECTORY",
	0xC00000BB: "STATUS_NOT_SUPPORTED",
	0xC00000CC: "STATUS_BAD_NETWORK_NAME",
	0xC00000D0: "STATUS_CANNOT_DELETE",
	0xC0000101: "STATUS_DIRECTORY_NOT_EMPTY",
	0xC0000102: "STATUS_NOT_A_DIRECTORY",
	0xC0000103: "STATUS_TOO_MANY_OPENED_FILES",
	0xC0000120: "STATUS_CANCELLED",
	0xC0000121: "STATUS_CANNOT_DELETE_SPECIAL",
	0xC0000123: "STATUS_FILE_DELETED",
	0xC0000128: "STATUS_FILE_CLOSED",
	0xC000015B: "STATUS_LOGON_TYPE_NOT_GRANTED",
	0xC000018B: "STATUS_NO_TRUST_SAM_ACCOUNT",
	0xC000018C: "STATUS_TRUSTED_DOMAIN_FAILURE",
	0xC000018D: "STATUS_TRUSTED_RELATIONSHIP_FAILURE",
	0xC000019B: "STATUS_TRUST_FAILURE",
	0xC0000203: "STATUS_USER_SESSION_DELETED",
	0xC0000224: "STATUS_PASSWORD_MUST_CHANGE",
	0xC0000234: "STATUS_ACCOUNT_LOCKED_OUT",
	0xC00002CC: "STATUS_BAD_NETWORK_PATH",
	0xC0000380: "STATUS_SMB_BAD_CLUSTER_DIALECT",
}

// Access mask flags for security monitoring
var accessMaskFlags = map[uint32]string{
	0x00000001: "READ_DATA/LIST_DIRECTORY",
	0x00000002: "WRITE_DATA/ADD_FILE",
	0x00000004: "APPEND_DATA/ADD_SUBDIRECTORY",
	0x00000008: "READ_EA",
	0x00000010: "WRITE_EA",
	0x00000020: "EXECUTE/TRAVERSE",
	0x00000040: "DELETE_CHILD",
	0x00000080: "READ_ATTRIBUTES",
	0x00000100: "WRITE_ATTRIBUTES",
	0x00010000: "DELETE",
	0x00020000: "READ_CONTROL",
	0x00040000: "WRITE_DAC",
	0x00080000: "WRITE_OWNER",
	0x00100000: "SYNCHRONIZE",
	0x01000000: "ACCESS_SYSTEM_SECURITY",
	0x02000000: "MAXIMUM_ALLOWED",
	0x10000000: "GENERIC_ALL",
	0x20000000: "GENERIC_EXECUTE",
	0x40000000: "GENERIC_WRITE",
	0x80000000: "GENERIC_READ",
}

// Create disposition values
var createDispositionNames = map[uint32]string{
	0: "FILE_SUPERSEDE",
	1: "FILE_OPEN",
	2: "FILE_CREATE",
	3: "FILE_OPEN_IF",
	4: "FILE_OVERWRITE",
	5: "FILE_OVERWRITE_IF",
}

// Share types
var shareTypeNames = map[uint8]string{
	0x00: "DISK",
	0x01: "PRINTER",
	0x02: "PIPE",
	0x03: "COMM",
}

// smbReader implements the stream decoder interface for SMB
type smbReader struct {
	conversation *core.ConversationInfo

	// Session state tracking
	version      int
	dialect      string
	sessionID    uint64
	treeID       uint32
	messageID    uint64
	clientGUID   string
	serverGUID   string
	capabilities []string
	isSigning    bool

	// Authentication tracking
	username    string
	domain      string
	workstation string
	ntlmVersion string
	authStatus  string

	// Share and file tracking
	shareName      string
	shareType      string
	filename       string
	fileID         uint64
	accessMask     uint32
	createDisp     uint32
	fileAttributes uint32
	isDirectory    bool

	// Data transfer tracking
	bytesTransferred int64
	offset           int64
	action           string

	// Pending requests for request/response correlation
	pendingRequests map[uint64]*pendingRequest
}

// pendingRequest tracks SMB requests awaiting responses
type pendingRequest struct {
	command    uint16
	messageID  uint64
	filename   string
	shareName  string
	accessMask uint32
	createDisp uint32
}

// New creates a new SMB stream decoder
func (s *smbReader) New(conversation *core.ConversationInfo) core.StreamDecoderInterface {
	return &smbReader{
		conversation:    conversation,
		pendingRequests: make(map[uint64]*pendingRequest),
	}
}

// Decode parses the SMB conversation using the standard conversation decoder
func (s *smbReader) Decode() {
	smbLog.Debug("Decoding SMB conversation",
		zap.String("ident", s.conversation.Ident),
		zap.String("clientIP", s.conversation.ClientIP),
		zap.String("serverIP", s.conversation.ServerIP),
	)

	streamutils.DecodeConversation(
		s.conversation.Ident,
		s.conversation.Data,
		func(b *bufio.Reader) error {
			return s.readSMBMessage(b, true) // client to server (request)
		},
		func(b *bufio.Reader) error {
			return s.readSMBMessage(b, false) // server to client (response)
		},
	)
}

// resetMessageState clears per-message state to prevent data bleeding between messages
func (s *smbReader) resetMessageState() {
	s.filename = ""
	s.action = ""
	s.accessMask = 0
	s.createDisp = 0
	s.fileAttributes = 0
	s.fileID = 0
	s.isDirectory = false
	s.bytesTransferred = 0
	s.offset = 0
	// Note: Don't reset session-level state like username, domain, sessionID, etc.
}

// readSMBMessage reads and parses an SMB message
func (s *smbReader) readSMBMessage(b *bufio.Reader, isClient bool) error {
	// Reset per-message state
	s.resetMessageState()
	// Read NetBIOS session service header (4 bytes)
	// Format: Type (1 byte) + Length (3 bytes, big-endian)
	nbHeader := make([]byte, 4)
	_, err := io.ReadFull(b, nbHeader)
	if err != nil {
		return err
	}

	// NetBIOS session message type should be 0x00 (Session Message)
	// Other types: 0x81 (Session Request), 0x82 (Positive Response), etc.
	if nbHeader[0] != 0x00 {
		// Not a session message, might be session setup or keep-alive
		smbLog.Debug("Non-session NetBIOS message",
			zap.Uint8("type", nbHeader[0]),
			zap.String("ident", s.conversation.Ident),
		)
		return nil
	}

	// Calculate message length (24-bit big-endian)
	msgLen := int(nbHeader[1])<<16 | int(nbHeader[2])<<8 | int(nbHeader[3])
	if msgLen < 4 {
		return nil
	}

	// Safety check for message length
	if msgLen > 4*1024*1024 { // 4MB max
		smbLog.Warn("SMB message too large, skipping",
			zap.Int("length", msgLen),
			zap.String("ident", s.conversation.Ident),
		)
		return nil
	}

	// Read the SMB message
	msg := make([]byte, msgLen)
	_, err = io.ReadFull(b, msg)
	if err != nil {
		return err
	}

	// Check SMB signature and determine version
	if len(msg) < 4 {
		return nil
	}

	signature := string(msg[0:4])
	switch signature {
	case SMB1Signature:
		return s.parseSMB1Message(msg, isClient)
	case SMB2Signature:
		return s.parseSMB2Message(msg, isClient)
	default:
		smbLog.Debug("Unknown SMB signature",
			zap.String("signature", hex.EncodeToString(msg[0:4])),
			zap.String("ident", s.conversation.Ident),
		)
	}

	return nil
}

// parseSMB1Message parses an SMB1 protocol message
func (s *smbReader) parseSMB1Message(msg []byte, isClient bool) error {
	if len(msg) < 32 {
		return nil
	}

	s.version = 1

	// SMB1 Header structure (32 bytes):
	// Offset 0-3: Protocol (0xFF, 'S', 'M', 'B')
	// Offset 4: Command
	// Offset 5-8: NT Status
	// Offset 9: Flags
	// Offset 10-11: Flags2
	// Offset 12-13: PID High
	// Offset 14-21: Signature
	// Offset 22-23: Reserved
	// Offset 24-25: TID (Tree ID)
	// Offset 26-27: PID (Process ID)
	// Offset 28-29: UID (User ID)
	// Offset 30-31: MID (Multiplex ID)

	command := msg[4]
	status := binary.LittleEndian.Uint32(msg[5:9])
	flags := msg[9]
	flags2 := binary.LittleEndian.Uint16(msg[10:12])
	treeID := binary.LittleEndian.Uint16(msg[24:26])
	userID := binary.LittleEndian.Uint16(msg[28:30])
	multiplexID := binary.LittleEndian.Uint16(msg[30:32])

	s.treeID = uint32(treeID)

	// SMB1: Response flag is in Flags byte (bit 7)
	isResponse := (flags & 0x80) != 0
	commandName := getSMB1CommandName(command)

	// Parse command-specific data
	wordCount := 0
	paramWords := []byte{}
	byteCount := 0
	dataBytes := []byte{}

	if len(msg) > 32 {
		wordCount = int(msg[32])
		paramOffset := 33
		paramEnd := paramOffset + (wordCount * 2)
		if paramEnd <= len(msg) {
			paramWords = msg[paramOffset:paramEnd]
		}

		byteCountOffset := paramEnd
		if byteCountOffset+2 <= len(msg) {
			byteCount = int(binary.LittleEndian.Uint16(msg[byteCountOffset : byteCountOffset+2]))
			dataOffset := byteCountOffset + 2
			dataEnd := dataOffset + byteCount
			if dataEnd <= len(msg) {
				dataBytes = msg[dataOffset:dataEnd]
			}
		}
	}

	// Parse specific commands for security-relevant data
	switch command {
	case SMB1_COM_NEGOTIATE:
		s.parseSMB1Negotiate(paramWords, dataBytes, isResponse)
	case SMB1_COM_SESSION_SETUP_ANDX:
		s.parseSMB1SessionSetup(paramWords, dataBytes, isResponse, status)
	case SMB1_COM_TREE_CONNECT_ANDX:
		s.parseSMB1TreeConnect(paramWords, dataBytes, isResponse)
	case SMB1_COM_NT_CREATE_ANDX:
		s.parseSMB1NTCreate(paramWords, dataBytes, isResponse)
	case SMB1_COM_OPEN_ANDX, SMB1_COM_OPEN, SMB1_COM_CREATE:
		s.filename = extractSMB1Filename(dataBytes)
		s.action = "OPEN"
	case SMB1_COM_READ_ANDX, SMB1_COM_READ:
		s.action = "READ"
	case SMB1_COM_WRITE_ANDX, SMB1_COM_WRITE:
		s.action = "WRITE"
	case SMB1_COM_CLOSE:
		s.action = "CLOSE"
	case SMB1_COM_DELETE:
		s.filename = extractSMB1Filename(dataBytes)
		s.action = "DELETE"
	case SMB1_COM_RENAME:
		s.action = "RENAME"
	case SMB1_COM_TREE_DISCONNECT:
		s.action = "TREE_DISCONNECT"
	}

	// Determine operation type for security monitoring
	operationType := classifyOperation(command, s.action)

	// Check for potential security threats
	isPotentialThreat, threatIndicator := detectThreats(command, status, s.username, s.shareName, s.filename, s.accessMask)

	smbLog.Debug("SMB1 message parsed",
		zap.String("command", commandName),
		zap.Uint32("status", status),
		zap.Bool("isResponse", isResponse),
		zap.Uint16("userID", userID),
		zap.Uint16("multiplexID", multiplexID),
		zap.String("ident", s.conversation.Ident),
	)

	// Write audit record
	s.writeSMBRecord(
		int32(command),
		commandName,
		status,
		uint32(flags),
		uint32(flags2),
		isResponse,
		operationType,
		isPotentialThreat,
		threatIndicator,
	)

	return nil
}

// parseSMB2Message parses an SMB2/3 protocol message
func (s *smbReader) parseSMB2Message(msg []byte, isClient bool) error {
	if len(msg) < 64 {
		return nil
	}

	// SMB2 Header structure (64 bytes):
	// Offset 0-3: Protocol ID (0xFE, 'S', 'M', 'B')
	// Offset 4-5: Structure Size (64)
	// Offset 6-7: Credit Charge
	// Offset 8-11: NT Status / ChannelSequence
	// Offset 12-13: Command
	// Offset 14-15: Credit Request/Response
	// Offset 16-19: Flags
	// Offset 20-23: Next Command
	// Offset 24-31: Message ID
	// Offset 32-35: Reserved / Process ID
	// Offset 36-39: Tree ID
	// Offset 40-47: Session ID
	// Offset 48-63: Signature (16 bytes)

	structSize := binary.LittleEndian.Uint16(msg[4:6])
	if structSize != 64 {
		smbLog.Debug("Invalid SMB2 header size",
			zap.Uint16("size", structSize),
			zap.String("ident", s.conversation.Ident),
		)
		return nil
	}

	status := binary.LittleEndian.Uint32(msg[8:12])
	command := binary.LittleEndian.Uint16(msg[12:14])
	flags := binary.LittleEndian.Uint32(msg[16:20])
	messageID := binary.LittleEndian.Uint64(msg[24:32])
	treeID := binary.LittleEndian.Uint32(msg[36:40])
	sessionID := binary.LittleEndian.Uint64(msg[40:48])

	// Check if this is a response
	isResponse := (flags & SMB2_FLAGS_SERVER_TO_REDIR) != 0
	isSigned := (flags & SMB2_FLAGS_SIGNED) != 0

	s.version = 2
	s.messageID = messageID
	s.sessionID = sessionID
	s.treeID = treeID
	s.isSigning = isSigned

	commandName := getSMB2CommandName(command)
	body := msg[64:]

	// Parse command-specific data
	switch command {
	case SMB2_NEGOTIATE:
		s.parseSMB2Negotiate(body, isResponse)
	case SMB2_SESSION_SETUP:
		s.parseSMB2SessionSetup(body, isResponse, status)
	case SMB2_TREE_CONNECT:
		s.parseSMB2TreeConnect(body, isResponse)
	case SMB2_CREATE:
		s.parseSMB2Create(body, isResponse, messageID)
	case SMB2_CLOSE:
		s.action = "CLOSE"
		if len(body) >= 24 && !isResponse {
			s.fileID = binary.LittleEndian.Uint64(body[8:16])
		}
	case SMB2_READ:
		s.action = "READ"
		if len(body) >= 49 && !isResponse {
			// Request: Length at offset 4, Offset at 8, FileID at 16
			s.bytesTransferred = int64(binary.LittleEndian.Uint32(body[4:8]))
			s.offset = int64(binary.LittleEndian.Uint64(body[8:16]))
			s.fileID = binary.LittleEndian.Uint64(body[16:24])
		} else if len(body) >= 16 && isResponse {
			// Response: DataLength at offset 4
			s.bytesTransferred = int64(binary.LittleEndian.Uint32(body[4:8]))
		}
	case SMB2_WRITE:
		s.action = "WRITE"
		if len(body) >= 49 && !isResponse {
			// Request: Length at offset 4, Offset at 8, FileID at 16
			s.bytesTransferred = int64(binary.LittleEndian.Uint32(body[4:8]))
			s.offset = int64(binary.LittleEndian.Uint64(body[8:16]))
			s.fileID = binary.LittleEndian.Uint64(body[16:24])
		} else if len(body) >= 16 && isResponse {
			// Response: Count at offset 4
			s.bytesTransferred = int64(binary.LittleEndian.Uint32(body[4:8]))
		}
	case SMB2_LOCK:
		s.action = "LOCK"
	case SMB2_IOCTL:
		s.action = "IOCTL"
	case SMB2_QUERY_DIRECTORY:
		s.action = "QUERY_DIRECTORY"
	case SMB2_QUERY_INFO:
		s.action = "QUERY_INFO"
	case SMB2_SET_INFO:
		s.action = "SET_INFO"
	case SMB2_LOGOFF:
		s.action = "LOGOFF"
	case SMB2_TREE_DISCONNECT:
		s.action = "TREE_DISCONNECT"
	}

	// Determine operation type and detect threats
	operationType := classifySMB2Operation(command, s.action)
	isPotentialThreat, threatIndicator := detectThreats(uint8(command), status, s.username, s.shareName, s.filename, s.accessMask)

	smbLog.Debug("SMB2 message parsed",
		zap.String("command", commandName),
		zap.Uint32("status", status),
		zap.Bool("isResponse", isResponse),
		zap.Uint64("sessionID", sessionID),
		zap.Uint64("messageID", messageID),
		zap.String("ident", s.conversation.Ident),
	)

	// Write audit record
	s.writeSMBRecord(
		int32(command),
		commandName,
		status,
		flags,
		0,
		isResponse,
		operationType,
		isPotentialThreat,
		threatIndicator,
	)

	return nil
}

// parseSMB1Negotiate parses SMB1 NEGOTIATE command
func (s *smbReader) parseSMB1Negotiate(params, data []byte, isResponse bool) {
	if isResponse && len(params) >= 2 {
		dialectIndex := binary.LittleEndian.Uint16(params[0:2])
		s.dialect = fmt.Sprintf("SMB1 Dialect %d", dialectIndex)
	}
	s.action = "NEGOTIATE"
}

// parseSMB1SessionSetup parses SMB1 SESSION_SETUP_ANDX
func (s *smbReader) parseSMB1SessionSetup(params, data []byte, isResponse bool, status uint32) {
	s.action = "SESSION_SETUP"

	if isResponse {
		if status == 0 {
			s.authStatus = "SUCCESS"
		} else if status == 0xC0000016 { // STATUS_MORE_PROCESSING_REQUIRED
			s.authStatus = "IN_PROGRESS"
		} else {
			s.authStatus = "FAILED"
		}
		return
	}

	// Request parsing - try to extract username/domain from security blob
	// SMB1 uses NTLMSSP or other security packages
	if bytes.Contains(data, []byte("NTLMSSP")) {
		s.ntlmVersion = "NTLMv1"
		s.parseNTLMSSP(data)
	}
}

// parseSMB1TreeConnect parses SMB1 TREE_CONNECT_ANDX
func (s *smbReader) parseSMB1TreeConnect(params, data []byte, isResponse bool) {
	s.action = "TREE_CONNECT"

	if !isResponse && len(data) > 0 {
		// Data contains: Password + Path + Service
		// Path is typically in format \\server\share
		s.shareName = extractSMB1SharePath(data)
	}
}

// parseSMB1NTCreate parses SMB1 NT_CREATE_ANDX
func (s *smbReader) parseSMB1NTCreate(params, data []byte, isResponse bool) {
	s.action = "CREATE"

	if !isResponse {
		if len(params) >= 24 {
			// Access mask at offset 4-7
			s.accessMask = binary.LittleEndian.Uint32(params[4:8])
			// Create disposition at offset 16-19
			s.createDisp = binary.LittleEndian.Uint32(params[16:20])
		}
		s.filename = extractSMB1Filename(data)
	} else if len(params) >= 12 {
		// Response contains FileID
		// This is the FID (File ID) which is 16-bit in SMB1
		s.fileID = uint64(binary.LittleEndian.Uint16(params[2:4]))
		// Check if directory
		s.isDirectory = (params[11] & 0x01) != 0
	}
}

// parseSMB2Negotiate parses SMB2 NEGOTIATE command
func (s *smbReader) parseSMB2Negotiate(body []byte, isResponse bool) {
	s.action = "NEGOTIATE"

	if isResponse && len(body) >= 65 {
		// SMB2 NEGOTIATE Response structure
		// Offset 4-5: Dialect Revision
		dialectRev := binary.LittleEndian.Uint16(body[4:6])
		s.dialect = formatDialect(dialectRev)

		// Check SMB3 (dialect >= 0x0300)
		if dialectRev >= 0x0300 {
			s.version = 3
		}

		// Offset 8-23: Server GUID (16 bytes)
		if len(body) >= 24 {
			s.serverGUID = formatGUID(body[8:24])
		}

		// Offset 24-27: Capabilities
		if len(body) >= 28 {
			caps := binary.LittleEndian.Uint32(body[24:28])
			s.capabilities = parseSMB2Capabilities(caps)
		}
	} else if !isResponse && len(body) >= 36 {
		// SMB2 NEGOTIATE Request
		// Offset 4-5: Dialect Count
		dialectCount := int(binary.LittleEndian.Uint16(body[4:6]))

		// Offset 12-27: Client GUID (16 bytes)
		if len(body) >= 28 {
			s.clientGUID = formatGUID(body[12:28])
		}

		// Collect requested dialects
		dialects := []string{}
		dialectOffset := 36
		for i := 0; i < dialectCount && dialectOffset+2 <= len(body); i++ {
			d := binary.LittleEndian.Uint16(body[dialectOffset : dialectOffset+2])
			dialects = append(dialects, formatDialect(d))
			dialectOffset += 2
		}
		if len(dialects) > 0 {
			s.dialect = strings.Join(dialects, ",")
		}
	}
}

// parseSMB2SessionSetup parses SMB2 SESSION_SETUP command
func (s *smbReader) parseSMB2SessionSetup(body []byte, isResponse bool, status uint32) {
	s.action = "SESSION_SETUP"

	if isResponse {
		if status == 0 {
			s.authStatus = "SUCCESS"
		} else if status == 0xC0000016 { // STATUS_MORE_PROCESSING_REQUIRED
			s.authStatus = "IN_PROGRESS"
		} else {
			s.authStatus = "FAILED"
		}
	}

	// Look for NTLMSSP in security buffer
	if bytes.Contains(body, []byte("NTLMSSP")) {
		s.parseNTLMSSP(body)
	}
}

// parseSMB2TreeConnect parses SMB2 TREE_CONNECT command
func (s *smbReader) parseSMB2TreeConnect(body []byte, isResponse bool) {
	s.action = "TREE_CONNECT"

	if isResponse && len(body) >= 16 {
		// SMB2 TREE_CONNECT Response
		// Offset 2: Share Type
		shareType := body[2]
		if name, ok := shareTypeNames[shareType]; ok {
			s.shareType = name
		}
	} else if !isResponse && len(body) >= 8 {
		// SMB2 TREE_CONNECT Request structure:
		// Offset 0-1: StructureSize (9)
		// Offset 2-3: Flags/Reserved
		// Offset 4-5: PathOffset (from start of SMB2 header)
		// Offset 6-7: PathLength
		rawPathOffset := int(binary.LittleEndian.Uint16(body[4:6]))
		pathLen := int(binary.LittleEndian.Uint16(body[6:8]))

		// PathOffset is from start of SMB2 header (offset 0), body starts at offset 64
		// So the path in body is at: rawPathOffset - 64
		pathOffset := rawPathOffset - 64
		if pathOffset >= 0 && pathOffset+pathLen <= len(body) {
			s.shareName = decodeUTF16LE(body[pathOffset : pathOffset+pathLen])
		}
	}
}

// parseSMB2Create parses SMB2 CREATE command
func (s *smbReader) parseSMB2Create(body []byte, isResponse bool, messageID uint64) {
	s.action = "CREATE"

	if !isResponse && len(body) >= 57 {
		// SMB2 CREATE Request structure (body starts at header offset 64)
		// Offset 0-1: StructureSize (57)
		// Offset 24-27: DesiredAccess
		s.accessMask = binary.LittleEndian.Uint32(body[24:28])

		// Offset 28-31: FileAttributes
		s.fileAttributes = binary.LittleEndian.Uint32(body[28:32])

		// Offset 36-39: CreateDisposition
		s.createDisp = binary.LittleEndian.Uint32(body[36:40])

		// Offset 44-45: NameOffset (from start of SMB2 header)
		// Offset 46-47: NameLength
		rawNameOffset := int(binary.LittleEndian.Uint16(body[44:46]))
		nameLen := int(binary.LittleEndian.Uint16(body[46:48]))

		// NameOffset is from start of SMB2 header, body starts at offset 64
		nameOffset := rawNameOffset - 64
		if nameOffset >= 0 && nameOffset+nameLen <= len(body) && nameLen > 0 {
			s.filename = decodeUTF16LE(body[nameOffset : nameOffset+nameLen])
		}

		// Store pending request for response correlation
		s.pendingRequests[messageID] = &pendingRequest{
			command:    SMB2_CREATE,
			messageID:  messageID,
			filename:   s.filename,
			accessMask: s.accessMask,
			createDisp: s.createDisp,
		}

	} else if isResponse && len(body) >= 88 {
		// SMB2 CREATE Response structure
		// Offset 4: OplockLevel
		// Offset 5: Flags (bit 0 = is directory)
		s.isDirectory = (body[5] & 0x01) != 0

		// Offset 64-71: FileId.Persistent
		// Offset 72-79: FileId.Volatile
		s.fileID = binary.LittleEndian.Uint64(body[64:72])

		// Try to get filename and access info from pending request
		if pending, ok := s.pendingRequests[messageID]; ok {
			s.filename = pending.filename
			s.accessMask = pending.accessMask
			s.createDisp = pending.createDisp
			delete(s.pendingRequests, messageID)
		}
	}
}

// NTLMTargetInfo attribute types (AV_PAIR)
const (
	MsvAvEOL             = 0x0000
	MsvAvNbComputerName  = 0x0001
	MsvAvNbDomainName    = 0x0002
	MsvAvDnsComputerName = 0x0003
	MsvAvDnsDomainName   = 0x0004
	MsvAvDnsTreeName     = 0x0005
	MsvAvFlags           = 0x0006
	MsvAvTimestamp       = 0x0007
	MsvAvSingleHost      = 0x0008
	MsvAvTargetName      = 0x0009
	MsvAvChannelBindings = 0x000A
)

// ntlmChallengeInfo holds parsed NTLM challenge data
type ntlmChallengeInfo struct {
	TargetName      string
	ServerChallenge string
	NbComputerName  string
	NbDomainName    string
	DnsComputerName string
	DnsDomainName   string
	DnsTreeName     string
	Timestamp       string
	NegotiateFlags  uint32
}

// parseNTLMSSP parses NTLMSSP security blob for authentication info
func (s *smbReader) parseNTLMSSP(data []byte) {
	// Find NTLMSSP signature
	idx := bytes.Index(data, []byte("NTLMSSP\x00"))
	if idx < 0 {
		return
	}

	ntlmssp := data[idx:]
	if len(ntlmssp) < 12 {
		return
	}

	// Message type at offset 8
	msgType := binary.LittleEndian.Uint32(ntlmssp[8:12])

	switch msgType {
	case 1: // NEGOTIATE_MESSAGE
		s.parseNTLMNegotiate(ntlmssp)

	case 2: // CHALLENGE_MESSAGE
		s.parseNTLMChallenge(ntlmssp)

	case 3: // AUTHENTICATE_MESSAGE
		s.parseNTLMAuthenticate(ntlmssp)
	}
}

// parseNTLMNegotiate parses NTLM NEGOTIATE message (Type 1)
func (s *smbReader) parseNTLMNegotiate(ntlmssp []byte) {
	if len(ntlmssp) < 32 {
		return
	}

	// Offset 12-15: NegotiateFlags
	flags := binary.LittleEndian.Uint32(ntlmssp[12:16])

	// Check for NTLMv2 indicators in flags
	// NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY (0x00080000) indicates NTLMv2 capable
	if flags&0x00080000 != 0 {
		s.ntlmVersion = "NTLMv2"
	} else {
		s.ntlmVersion = "NTLMv1"
	}

	smbLog.Debug("NTLM NEGOTIATE parsed",
		zap.String("ntlmVersion", s.ntlmVersion),
		zap.Uint32("flags", flags),
		zap.String("ident", s.conversation.Ident),
	)
}

// parseNTLMChallenge parses NTLM CHALLENGE message (Type 2)
func (s *smbReader) parseNTLMChallenge(ntlmssp []byte) {
	if len(ntlmssp) < 56 {
		return
	}

	// NTLM CHALLENGE structure:
	// Offset 0-7: Signature "NTLMSSP\0"
	// Offset 8-11: MessageType (2)
	// Offset 12-13: TargetNameLen
	// Offset 14-15: TargetNameMaxLen
	// Offset 16-19: TargetNameBufferOffset
	// Offset 20-23: NegotiateFlags
	// Offset 24-31: ServerChallenge (8 bytes)
	// Offset 32-39: Reserved (8 bytes)
	// Offset 40-41: TargetInfoLen
	// Offset 42-43: TargetInfoMaxLen
	// Offset 44-47: TargetInfoBufferOffset
	// Offset 48-55: Version (optional, 8 bytes)

	challengeInfo := &ntlmChallengeInfo{}

	// Parse NegotiateFlags
	challengeInfo.NegotiateFlags = binary.LittleEndian.Uint32(ntlmssp[20:24])

	// Check NTLMv2 capability
	if challengeInfo.NegotiateFlags&0x00080000 != 0 {
		s.ntlmVersion = "NTLMv2"
	}

	// Extract ServerChallenge (8 bytes at offset 24)
	challengeInfo.ServerChallenge = hex.EncodeToString(ntlmssp[24:32])

	// Parse TargetName
	targetNameLen := int(binary.LittleEndian.Uint16(ntlmssp[12:14]))
	targetNameOffset := int(binary.LittleEndian.Uint32(ntlmssp[16:20]))
	if targetNameOffset > 0 && targetNameOffset+targetNameLen <= len(ntlmssp) {
		challengeInfo.TargetName = decodeUTF16LE(ntlmssp[targetNameOffset : targetNameOffset+targetNameLen])
		// Use target name as domain if not yet set
		if s.domain == "" {
			s.domain = challengeInfo.TargetName
		}
	}

	// Parse TargetInfo (AV_PAIR list) if NTLMSSP_NEGOTIATE_TARGET_INFO flag is set
	if challengeInfo.NegotiateFlags&0x00800000 != 0 && len(ntlmssp) >= 48 {
		targetInfoLen := int(binary.LittleEndian.Uint16(ntlmssp[40:42]))
		targetInfoOffset := int(binary.LittleEndian.Uint32(ntlmssp[44:48]))

		if targetInfoOffset > 0 && targetInfoOffset+targetInfoLen <= len(ntlmssp) {
			s.parseNTLMTargetInfo(ntlmssp[targetInfoOffset:targetInfoOffset+targetInfoLen], challengeInfo)
		}
	}

	// Update smbReader with extracted info
	if challengeInfo.NbDomainName != "" && s.domain == "" {
		s.domain = challengeInfo.NbDomainName
	}
	if challengeInfo.DnsDomainName != "" && s.domain == "" {
		s.domain = challengeInfo.DnsDomainName
	}
	if challengeInfo.NbComputerName != "" {
		// This is the server's computer name
		s.serverGUID = challengeInfo.NbComputerName
	}

	smbLog.Debug("NTLM CHALLENGE parsed",
		zap.String("targetName", challengeInfo.TargetName),
		zap.String("serverChallenge", challengeInfo.ServerChallenge),
		zap.String("nbDomainName", challengeInfo.NbDomainName),
		zap.String("nbComputerName", challengeInfo.NbComputerName),
		zap.String("dnsDomainName", challengeInfo.DnsDomainName),
		zap.String("dnsComputerName", challengeInfo.DnsComputerName),
		zap.String("ident", s.conversation.Ident),
	)
}

// parseNTLMTargetInfo parses the AV_PAIR list from NTLM CHALLENGE
func (s *smbReader) parseNTLMTargetInfo(data []byte, info *ntlmChallengeInfo) {
	offset := 0
	for offset+4 <= len(data) {
		avID := binary.LittleEndian.Uint16(data[offset : offset+2])
		avLen := int(binary.LittleEndian.Uint16(data[offset+2 : offset+4]))
		offset += 4

		if avID == MsvAvEOL || offset+avLen > len(data) {
			break
		}

		value := data[offset : offset+avLen]
		offset += avLen

		switch avID {
		case MsvAvNbComputerName:
			info.NbComputerName = decodeUTF16LE(value)
		case MsvAvNbDomainName:
			info.NbDomainName = decodeUTF16LE(value)
		case MsvAvDnsComputerName:
			info.DnsComputerName = decodeUTF16LE(value)
		case MsvAvDnsDomainName:
			info.DnsDomainName = decodeUTF16LE(value)
		case MsvAvDnsTreeName:
			info.DnsTreeName = decodeUTF16LE(value)
		case MsvAvTimestamp:
			if len(value) == 8 {
				// Windows FILETIME (100-nanosecond intervals since Jan 1, 1601)
				ft := binary.LittleEndian.Uint64(value)
				info.Timestamp = fmt.Sprintf("%d", ft)
			}
		}
	}
}

// parseNTLMAuthenticate parses NTLM AUTHENTICATE message (Type 3)
func (s *smbReader) parseNTLMAuthenticate(ntlmssp []byte) {
	if len(ntlmssp) < 64 {
		return
	}

	// NTLM AUTHENTICATE structure:
	// Offset 12-19: LmChallengeResponse
	// Offset 20-27: NtChallengeResponse
	// Offset 28-35: DomainName
	// Offset 36-43: UserName
	// Offset 44-51: Workstation
	// Offset 52-59: EncryptedRandomSessionKey
	// Offset 60-63: NegotiateFlags

	// Parse NegotiateFlags to determine NTLMv1 vs NTLMv2
	if len(ntlmssp) >= 64 {
		flags := binary.LittleEndian.Uint32(ntlmssp[60:64])
		if flags&0x00080000 != 0 {
			s.ntlmVersion = "NTLMv2"
		} else {
			s.ntlmVersion = "NTLMv1"
		}
	}

	// Domain: offset 28-35 (length, max length, offset)
	domainLen := binary.LittleEndian.Uint16(ntlmssp[28:30])
	domainOffset := binary.LittleEndian.Uint32(ntlmssp[32:36])
	if domainOffset > 0 && int(domainOffset+uint32(domainLen)) <= len(ntlmssp) {
		s.domain = decodeUTF16LE(ntlmssp[domainOffset : domainOffset+uint32(domainLen)])
	}

	// Username: offset 36-43
	userLen := binary.LittleEndian.Uint16(ntlmssp[36:38])
	userOffset := binary.LittleEndian.Uint32(ntlmssp[40:44])
	if userOffset > 0 && int(userOffset+uint32(userLen)) <= len(ntlmssp) {
		s.username = decodeUTF16LE(ntlmssp[userOffset : userOffset+uint32(userLen)])
	}

	// Workstation: offset 44-51
	wsLen := binary.LittleEndian.Uint16(ntlmssp[44:46])
	wsOffset := binary.LittleEndian.Uint32(ntlmssp[48:52])
	if wsOffset > 0 && int(wsOffset+uint32(wsLen)) <= len(ntlmssp) {
		s.workstation = decodeUTF16LE(ntlmssp[wsOffset : wsOffset+uint32(wsLen)])
	}

	smbLog.Debug("NTLM AUTHENTICATE parsed",
		zap.String("username", s.username),
		zap.String("domain", s.domain),
		zap.String("workstation", s.workstation),
		zap.String("ntlmVersion", s.ntlmVersion),
		zap.String("ident", s.conversation.Ident),
	)
}

// Helper functions

func extractSMB1Filename(data []byte) string {
	// SMB1 filenames are typically null-terminated ASCII or UTF-16LE
	if len(data) == 0 {
		return ""
	}

	// Check for UTF-16LE (starts with non-null, has null bytes)
	if len(data) >= 2 && data[1] == 0 {
		return decodeUTF16LE(data)
	}

	// ASCII
	end := bytes.IndexByte(data, 0)
	if end > 0 {
		return string(data[:end])
	}
	return string(data)
}

func extractSMB1SharePath(data []byte) string {
	// SMB1 share path is typically \\server\share followed by null
	// Skip password if present (first null-terminated string)
	idx := bytes.IndexByte(data, 0)
	if idx >= 0 && idx+1 < len(data) {
		pathData := data[idx+1:]
		end := bytes.IndexByte(pathData, 0)
		if end > 0 {
			return string(pathData[:end])
		}
	}
	return ""
}

func decodeUTF16LE(data []byte) string {
	if len(data) < 2 {
		return ""
	}

	// Convert bytes to UTF-16 code units
	u16s := make([]uint16, len(data)/2)
	for i := 0; i < len(u16s); i++ {
		u16s[i] = binary.LittleEndian.Uint16(data[i*2:])
	}

	// Convert to string
	runes := utf16.Decode(u16s)
	return strings.TrimRight(string(runes), "\x00")
}

func formatGUID(data []byte) string {
	if len(data) < 16 {
		return ""
	}
	// GUID format: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
	// First 3 components are little-endian, last 2 are big-endian (as bytes)
	return fmt.Sprintf("%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
		binary.LittleEndian.Uint32(data[0:4]),
		binary.LittleEndian.Uint16(data[4:6]),
		binary.LittleEndian.Uint16(data[6:8]),
		data[8], data[9],
		data[10], data[11], data[12], data[13], data[14], data[15])
}

func formatDialect(dialect uint16) string {
	switch dialect {
	case 0x0202:
		return "SMB 2.0.2"
	case 0x0210:
		return "SMB 2.1"
	case 0x0300:
		return "SMB 3.0"
	case 0x0302:
		return "SMB 3.0.2"
	case 0x0311:
		return "SMB 3.1.1"
	case 0x02FF:
		return "SMB2_WILDCARD"
	default:
		return fmt.Sprintf("Unknown (0x%04X)", dialect)
	}
}

func parseSMB2Capabilities(caps uint32) []string {
	result := []string{}
	capNames := map[uint32]string{
		0x00000001: "DFS",
		0x00000002: "LEASING",
		0x00000004: "LARGE_MTU",
		0x00000008: "MULTI_CHANNEL",
		0x00000010: "PERSISTENT_HANDLES",
		0x00000020: "DIRECTORY_LEASING",
		0x00000040: "ENCRYPTION",
	}
	for bit, name := range capNames {
		if caps&bit != 0 {
			result = append(result, name)
		}
	}
	return result
}

func formatAccessMask(mask uint32) string {
	if mask == 0 {
		return ""
	}

	parts := []string{}
	for bit, name := range accessMaskFlags {
		if mask&bit != 0 {
			parts = append(parts, name)
		}
	}

	if len(parts) == 0 {
		return fmt.Sprintf("0x%08X", mask)
	}
	return strings.Join(parts, "|")
}

func formatCreateDisposition(disp uint32) string {
	if name, ok := createDispositionNames[disp]; ok {
		return name
	}
	return fmt.Sprintf("UNKNOWN(0x%X)", disp)
}

func classifyOperation(cmd uint8, action string) string {
	switch cmd {
	case SMB1_COM_NEGOTIATE:
		return "NEGOTIATE"
	case SMB1_COM_SESSION_SETUP_ANDX:
		return "AUTHENTICATION"
	case SMB1_COM_TREE_CONNECT, SMB1_COM_TREE_CONNECT_ANDX:
		return "SHARE_ACCESS"
	case SMB1_COM_NT_CREATE_ANDX, SMB1_COM_OPEN, SMB1_COM_OPEN_ANDX, SMB1_COM_CREATE:
		return "FILE_ACCESS"
	case SMB1_COM_READ, SMB1_COM_READ_ANDX:
		return "FILE_READ"
	case SMB1_COM_WRITE, SMB1_COM_WRITE_ANDX:
		return "FILE_WRITE"
	case SMB1_COM_DELETE:
		return "FILE_DELETE"
	case SMB1_COM_RENAME:
		return "FILE_RENAME"
	case SMB1_COM_CLOSE:
		return "FILE_CLOSE"
	default:
		if action != "" {
			return action
		}
		return "OTHER"
	}
}

func classifySMB2Operation(cmd uint16, action string) string {
	switch cmd {
	case SMB2_NEGOTIATE:
		return "NEGOTIATE"
	case SMB2_SESSION_SETUP:
		return "AUTHENTICATION"
	case SMB2_TREE_CONNECT:
		return "SHARE_ACCESS"
	case SMB2_CREATE:
		return "FILE_ACCESS"
	case SMB2_READ:
		return "FILE_READ"
	case SMB2_WRITE:
		return "FILE_WRITE"
	case SMB2_CLOSE:
		return "FILE_CLOSE"
	case SMB2_QUERY_DIRECTORY:
		return "DIRECTORY_LISTING"
	case SMB2_QUERY_INFO:
		return "FILE_QUERY"
	case SMB2_SET_INFO:
		return "FILE_MODIFY"
	case SMB2_LOGOFF:
		return "LOGOFF"
	case SMB2_TREE_DISCONNECT:
		return "SHARE_DISCONNECT"
	default:
		if action != "" {
			return action
		}
		return "OTHER"
	}
}

// detectThreats checks for potentially suspicious SMB activity
func detectThreats(cmd uint8, status uint32, username, share, filename string, accessMask uint32) (bool, string) {
	threats := []string{}

	// Authentication failures
	if status == 0xC000006D || status == 0xC000006A { // LOGON_FAILURE, WRONG_PASSWORD
		threats = append(threats, "AUTH_FAILURE")
	}

	// Account lockout
	if status == 0xC0000234 { // ACCOUNT_LOCKED_OUT
		threats = append(threats, "ACCOUNT_LOCKOUT")
	}

	// Account disabled
	if status == 0xC0000072 { // ACCOUNT_DISABLED
		threats = append(threats, "ACCOUNT_DISABLED")
	}

	// Password expired
	if status == 0xC0000071 || status == 0xC0000224 { // PASSWORD_EXPIRED, PASSWORD_MUST_CHANGE
		threats = append(threats, "PASSWORD_EXPIRED")
	}

	// Access denied
	if status == 0xC0000022 { // ACCESS_DENIED
		threats = append(threats, "ACCESS_DENIED")
	}

	// Privilege not held (potential privilege escalation attempt)
	if status == 0xC0000061 { // PRIVILEGE_NOT_HELD
		threats = append(threats, "PRIVILEGE_ESCALATION_ATTEMPT")
	}

	lowerFilename := strings.ToLower(filename)
	lowerShare := strings.ToLower(share)

	// Check for sensitive file access patterns
	sensitivePatterns := []string{
		"ntds.dit", "sam", "system", "security", // Windows security files
		"lsass", "lsass.dmp", "procdump", // Credential dumping
		"passwd", "shadow", "group", // Unix password files
		"id_rsa", "id_dsa", "id_ed25519", ".ssh", // SSH keys
		"web.config", "wp-config", ".htpasswd", // Web app configs
		"passwords", "credentials", "secrets", "vault",
		".kdbx", "keepass", ".pfx", ".p12", // Password managers/certs
		"mimikatz", "lazagne", "secretsdump", // Known credential tools
	}

	for _, pattern := range sensitivePatterns {
		if strings.Contains(lowerFilename, pattern) {
			threats = append(threats, "SENSITIVE_FILE_ACCESS")
			break
		}
	}

	// Check for admin share access
	adminShares := []string{"admin$", "c$", "d$", "e$", "ipc$"}
	for _, adminShare := range adminShares {
		if strings.Contains(lowerShare, adminShare) {
			// Any write access to admin shares is suspicious
			if accessMask&0x00010006 != 0 { // DELETE|WRITE_DATA|WRITE_ATTRIBUTES
				threats = append(threats, "ADMIN_SHARE_WRITE")
			}
			// Even read access to non-IPC admin shares can indicate recon
			if !strings.Contains(lowerShare, "ipc$") && accessMask&0x00000001 != 0 { // READ_DATA
				threats = append(threats, "ADMIN_SHARE_READ")
			}
			break
		}
	}

	// Check for executable file writes (lateral movement / malware deployment)
	execExtensions := []string{".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".msi", ".scr", ".com", ".pif", ".hta"}
	for _, ext := range execExtensions {
		if strings.HasSuffix(lowerFilename, ext) && accessMask&0x00000002 != 0 { // WRITE_DATA
			threats = append(threats, "EXECUTABLE_WRITE")
			break
		}
	}

	// Check for PsExec-style service creation patterns
	// PSEXESVC is the PSExec service executable
	if strings.Contains(lowerFilename, "psexec") || strings.Contains(lowerFilename, "psexesvc") ||
		strings.Contains(lowerFilename, "paexec") || strings.Contains(lowerFilename, "remcom") ||
		strings.Contains(lowerFilename, "csexec") || strings.Contains(lowerFilename, "winexesvc") {
		threats = append(threats, "REMOTE_EXEC_TOOL")
	}

	// Check for ransomware indicators (readme files in shares)
	ransomwareIndicators := []string{"readme", "decrypt", "restore", "recover", "ransom", "locked", "encrypted"}
	for _, indicator := range ransomwareIndicators {
		if strings.Contains(lowerFilename, indicator) && strings.HasSuffix(lowerFilename, ".txt") {
			threats = append(threats, "POTENTIAL_RANSOMWARE")
			break
		}
	}

	// Check for named pipe access (often used in attacks)
	if strings.Contains(lowerShare, "ipc$") && filename != "" {
		suspiciousPipes := []string{"svcctl", "atsvc", "samr", "lsarpc", "netlogon", "srvsvc", "wkssvc", "scerpc"}
		for _, pipe := range suspiciousPipes {
			if strings.Contains(lowerFilename, pipe) {
				threats = append(threats, "SENSITIVE_PIPE_ACCESS")
				break
			}
		}
	}

	if len(threats) > 0 {
		return true, strings.Join(threats, ",")
	}
	return false, ""
}

// writeSMBRecord writes an SMB audit record with all parsed information
func (s *smbReader) writeSMBRecord(
	command int32,
	commandName string,
	status uint32,
	flags uint32,
	flags2 uint32,
	isResponse bool,
	operationType string,
	isPotentialThreat bool,
	threatIndicator string,
) {
	if Decoder.Writer == nil {
		return
	}

	// Get NT status name
	statusName := ""
	if name, ok := ntStatusNames[status]; ok {
		statusName = name
	} else if status != 0 {
		statusName = fmt.Sprintf("STATUS_0x%08X", status)
	}

	smb := &types.SMB{
		Timestamp:            s.conversation.FirstClientPacket.UnixNano(),
		SrcIP:                s.conversation.ClientIP,
		DstIP:                s.conversation.ServerIP,
		SrcPort:              s.conversation.ClientPort,
		DstPort:              s.conversation.ServerPort,
		Version:              int32(s.version),
		Command:              command,
		CommandName:          commandName,
		Status:               status,
		StatusName:           statusName,
		Flags:                flags,
		Flags2:               flags2,
		IsResponse:           isResponse,
		Username:             s.username,
		Domain:               s.domain,
		Workstation:          s.workstation,
		NTLMVersion:          s.ntlmVersion,
		AuthStatus:           s.authStatus,
		ShareName:            s.shareName,
		ShareType:            s.shareType,
		Filename:             s.filename,
		FileID:               s.fileID,
		Action:               s.action,
		BytesTransferred:     s.bytesTransferred,
		Offset:               s.offset,
		AccessMask:           s.accessMask,
		AccessMaskStr:        formatAccessMask(s.accessMask),
		CreateDisposition:    s.createDisp,
		CreateDispositionStr: formatCreateDisposition(s.createDisp),
		FileAttributes:       s.fileAttributes,
		IsDirectory:          s.isDirectory,
		SessionID:            s.sessionID,
		TreeID:               s.treeID,
		MessageID:            s.messageID,
		IsSigned:             s.isSigning,
		DialectRevision:      s.dialect,
		ClientGUID:           s.clientGUID,
		ServerGUID:           s.serverGUID,
		Capabilities:         s.capabilities,
		OperationType:        operationType,
		IsPotentialThreat:    isPotentialThreat,
		ThreatIndicator:      threatIndicator,
	}

	// Swap src/dst for responses (server is responding)
	if isResponse {
		smb.SrcIP = s.conversation.ServerIP
		smb.DstIP = s.conversation.ClientIP
		smb.SrcPort = s.conversation.ServerPort
		smb.DstPort = s.conversation.ClientPort
	}

	atomic.AddInt64(&Decoder.NumRecordsWritten, 1)
	err := Decoder.Writer.Write(smb)
	if err != nil {
		decoderutils.ErrorMap.Inc(err.Error())
	}
}

// SMB1 command name mapping (comprehensive)
func getSMB1CommandName(cmd uint8) string {
	names := map[uint8]string{
		SMB1_COM_CREATE_DIRECTORY:      "CREATE_DIRECTORY",
		SMB1_COM_DELETE_DIRECTORY:      "DELETE_DIRECTORY",
		SMB1_COM_OPEN:                  "OPEN",
		SMB1_COM_CREATE:                "CREATE",
		SMB1_COM_CLOSE:                 "CLOSE",
		SMB1_COM_FLUSH:                 "FLUSH",
		SMB1_COM_DELETE:                "DELETE",
		SMB1_COM_RENAME:                "RENAME",
		SMB1_COM_QUERY_INFORMATION:     "QUERY_INFORMATION",
		SMB1_COM_SET_INFORMATION:       "SET_INFORMATION",
		SMB1_COM_READ:                  "READ",
		SMB1_COM_WRITE:                 "WRITE",
		SMB1_COM_LOCK_BYTE_RANGE:       "LOCK_BYTE_RANGE",
		SMB1_COM_UNLOCK_BYTE_RANGE:     "UNLOCK_BYTE_RANGE",
		SMB1_COM_CREATE_TEMPORARY:      "CREATE_TEMPORARY",
		SMB1_COM_CREATE_NEW:            "CREATE_NEW",
		SMB1_COM_CHECK_DIRECTORY:       "CHECK_DIRECTORY",
		SMB1_COM_PROCESS_EXIT:          "PROCESS_EXIT",
		SMB1_COM_SEEK:                  "SEEK",
		SMB1_COM_LOCK_AND_READ:         "LOCK_AND_READ",
		SMB1_COM_WRITE_AND_UNLOCK:      "WRITE_AND_UNLOCK",
		SMB1_COM_READ_RAW:              "READ_RAW",
		SMB1_COM_READ_MPX:              "READ_MPX",
		SMB1_COM_WRITE_RAW:             "WRITE_RAW",
		SMB1_COM_WRITE_MPX:             "WRITE_MPX",
		SMB1_COM_WRITE_COMPLETE:        "WRITE_COMPLETE",
		SMB1_COM_LOCKING_ANDX:          "LOCKING_ANDX",
		SMB1_COM_TRANSACTION:           "TRANSACTION",
		SMB1_COM_TRANSACTION_SECONDARY: "TRANSACTION_SECONDARY",
		SMB1_COM_IOCTL:                 "IOCTL",
		SMB1_COM_ECHO:                  "ECHO",
		SMB1_COM_WRITE_AND_CLOSE:       "WRITE_AND_CLOSE",
		SMB1_COM_OPEN_ANDX:             "OPEN_ANDX",
		SMB1_COM_READ_ANDX:             "READ_ANDX",
		SMB1_COM_WRITE_ANDX:            "WRITE_ANDX",
		SMB1_COM_TRANSACTION2:          "TRANSACTION2",
		SMB1_COM_FIND_CLOSE2:           "FIND_CLOSE2",
		SMB1_COM_TREE_CONNECT:          "TREE_CONNECT",
		SMB1_COM_TREE_DISCONNECT:       "TREE_DISCONNECT",
		SMB1_COM_NEGOTIATE:             "NEGOTIATE",
		SMB1_COM_SESSION_SETUP_ANDX:    "SESSION_SETUP_ANDX",
		SMB1_COM_LOGOFF_ANDX:           "LOGOFF_ANDX",
		SMB1_COM_TREE_CONNECT_ANDX:     "TREE_CONNECT_ANDX",
		SMB1_COM_NT_TRANSACT:           "NT_TRANSACT",
		SMB1_COM_NT_CREATE_ANDX:        "NT_CREATE_ANDX",
		SMB1_COM_NT_CANCEL:             "NT_CANCEL",
		SMB1_COM_NT_RENAME:             "NT_RENAME",
	}

	if name, ok := names[cmd]; ok {
		return name
	}
	return fmt.Sprintf("UNKNOWN(0x%02X)", cmd)
}

// SMB2 command name mapping
func getSMB2CommandName(cmd uint16) string {
	names := map[uint16]string{
		SMB2_NEGOTIATE:       "NEGOTIATE",
		SMB2_SESSION_SETUP:   "SESSION_SETUP",
		SMB2_LOGOFF:          "LOGOFF",
		SMB2_TREE_CONNECT:    "TREE_CONNECT",
		SMB2_TREE_DISCONNECT: "TREE_DISCONNECT",
		SMB2_CREATE:          "CREATE",
		SMB2_CLOSE:           "CLOSE",
		SMB2_FLUSH:           "FLUSH",
		SMB2_READ:            "READ",
		SMB2_WRITE:           "WRITE",
		SMB2_LOCK:            "LOCK",
		SMB2_IOCTL:           "IOCTL",
		SMB2_CANCEL:          "CANCEL",
		SMB2_ECHO:            "ECHO",
		SMB2_QUERY_DIRECTORY: "QUERY_DIRECTORY",
		SMB2_CHANGE_NOTIFY:   "CHANGE_NOTIFY",
		SMB2_QUERY_INFO:      "QUERY_INFO",
		SMB2_SET_INFO:        "SET_INFO",
		SMB2_OPLOCK_BREAK:    "OPLOCK_BREAK",
	}

	if name, ok := names[cmd]; ok {
		return name
	}
	return fmt.Sprintf("UNKNOWN(0x%04X)", cmd)
}
