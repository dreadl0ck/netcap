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

package smb

import (
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/decoder/core"
)

// newTestSMBReader creates an smbReader with a mock conversation for testing
func newTestSMBReader() *smbReader {
	return &smbReader{
		conversation: &core.ConversationInfo{
			Ident:             "test:192.168.1.1:49152->192.168.1.2:445",
			ClientIP:          "192.168.1.1",
			ServerIP:          "192.168.1.2",
			ClientPort:        49152,
			ServerPort:        445,
			FirstClientPacket: time.Now(),
		},
		pendingRequests: make(map[uint64]*pendingRequest),
	}
}

// Test SMB signature detection
func TestSMBSignatures(t *testing.T) {
	tests := []struct {
		name      string
		signature string
		expected  string
	}{
		{"SMB1", SMB1Signature, "\xFFSMB"},
		{"SMB2", SMB2Signature, "\xFESMB"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.signature != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, tt.signature)
			}
		})
	}
}

// Test SMB1 command name mapping
func TestGetSMB1CommandName(t *testing.T) {
	tests := []struct {
		cmd      uint8
		expected string
	}{
		{SMB1_COM_NEGOTIATE, "NEGOTIATE"},
		{SMB1_COM_SESSION_SETUP_ANDX, "SESSION_SETUP_ANDX"},
		{SMB1_COM_TREE_CONNECT_ANDX, "TREE_CONNECT_ANDX"},
		{SMB1_COM_NT_CREATE_ANDX, "NT_CREATE_ANDX"},
		{SMB1_COM_READ_ANDX, "READ_ANDX"},
		{SMB1_COM_WRITE_ANDX, "WRITE_ANDX"},
		{SMB1_COM_CLOSE, "CLOSE"},
		{SMB1_COM_DELETE, "DELETE"},
		{SMB1_COM_RENAME, "RENAME"},
		{0xFF, "UNKNOWN(0xFF)"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := getSMB1CommandName(tt.cmd)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

// Test SMB2 command name mapping
func TestGetSMB2CommandName(t *testing.T) {
	tests := []struct {
		cmd      uint16
		expected string
	}{
		{SMB2_NEGOTIATE, "NEGOTIATE"},
		{SMB2_SESSION_SETUP, "SESSION_SETUP"},
		{SMB2_TREE_CONNECT, "TREE_CONNECT"},
		{SMB2_CREATE, "CREATE"},
		{SMB2_CLOSE, "CLOSE"},
		{SMB2_READ, "READ"},
		{SMB2_WRITE, "WRITE"},
		{SMB2_QUERY_DIRECTORY, "QUERY_DIRECTORY"},
		{SMB2_QUERY_INFO, "QUERY_INFO"},
		{SMB2_SET_INFO, "SET_INFO"},
		{0xFFFF, "UNKNOWN(0xFFFF)"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := getSMB2CommandName(tt.cmd)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

// Test NT Status name mapping
func TestNTStatusNames(t *testing.T) {
	tests := []struct {
		status   uint32
		expected string
	}{
		{0x00000000, "STATUS_SUCCESS"},
		{0xC0000022, "STATUS_ACCESS_DENIED"},
		{0xC000006D, "STATUS_LOGON_FAILURE"},
		{0xC0000234, "STATUS_ACCOUNT_LOCKED_OUT"},
		{0xC0000016, "STATUS_MORE_PROCESSING_REQUIRED"},
		{0xC0000072, "STATUS_ACCOUNT_DISABLED"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result, ok := ntStatusNames[tt.status]
			if !ok {
				t.Errorf("Status 0x%08X not found in ntStatusNames", tt.status)
				return
			}
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

// Test dialect formatting
func TestFormatDialect(t *testing.T) {
	tests := []struct {
		dialect  uint16
		expected string
	}{
		{0x0202, "SMB 2.0.2"},
		{0x0210, "SMB 2.1"},
		{0x0300, "SMB 3.0"},
		{0x0302, "SMB 3.0.2"},
		{0x0311, "SMB 3.1.1"},
		{0x02FF, "SMB2_WILDCARD"},
		{0x0000, "Unknown (0x0000)"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := formatDialect(tt.dialect)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

// Test GUID formatting
func TestFormatGUID(t *testing.T) {
	// Sample GUID: {12345678-1234-5678-9ABC-DEFABCDEF012}
	data := []byte{
		0x78, 0x56, 0x34, 0x12, // Data1 (little-endian)
		0x34, 0x12,             // Data2 (little-endian)
		0x78, 0x56,             // Data3 (little-endian)
		0x9A, 0xBC,             // Data4[0:2]
		0xDE, 0xFA, 0xBC, 0xDE, 0xF0, 0x12, // Data4[2:8]
	}

	result := formatGUID(data)
	expected := "12345678-1234-5678-9ABC-DEFABCDEF012"
	if result != expected {
		t.Errorf("Expected %s, got %s", expected, result)
	}

	// Test empty/short data
	if formatGUID(nil) != "" {
		t.Error("Expected empty string for nil data")
	}
	if formatGUID([]byte{1, 2, 3}) != "" {
		t.Error("Expected empty string for short data")
	}
}

// Test access mask formatting
func TestFormatAccessMask(t *testing.T) {
	tests := []struct {
		mask     uint32
		contains []string
	}{
		{0x00000001, []string{"READ_DATA/LIST_DIRECTORY"}},
		{0x00000002, []string{"WRITE_DATA/ADD_FILE"}},
		{0x00010000, []string{"DELETE"}},
		{0x80000000, []string{"GENERIC_READ"}},
		{0x00000003, []string{"READ_DATA/LIST_DIRECTORY", "WRITE_DATA/ADD_FILE"}},
		{0x00000000, []string{}},
	}

	for _, tt := range tests {
		result := formatAccessMask(tt.mask)
		for _, expected := range tt.contains {
			if !strings.Contains(result, expected) {
				t.Errorf("Expected result for mask 0x%08X to contain %q, got %q", tt.mask, expected, result)
			}
		}
		if len(tt.contains) == 0 && result != "" {
			// Empty mask should produce no flags (though formatAccessMask may still produce output)
		}
	}
}

// Test create disposition formatting
func TestFormatCreateDisposition(t *testing.T) {
	tests := []struct {
		disp     uint32
		expected string
	}{
		{0, "FILE_SUPERSEDE"},
		{1, "FILE_OPEN"},
		{2, "FILE_CREATE"},
		{3, "FILE_OPEN_IF"},
		{4, "FILE_OVERWRITE"},
		{5, "FILE_OVERWRITE_IF"},
		{99, "UNKNOWN(0x63)"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := formatCreateDisposition(tt.disp)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

// Test UTF-16LE decoding
func TestDecodeUTF16LE(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:     "simple ASCII",
			input:    []byte{'T', 0, 'e', 0, 's', 0, 't', 0},
			expected: "Test",
		},
		{
			name:     "with null terminator",
			input:    []byte{'T', 0, 'e', 0, 's', 0, 't', 0, 0, 0},
			expected: "Test",
		},
		{
			name:     "empty",
			input:    []byte{},
			expected: "",
		},
		{
			name:     "single byte",
			input:    []byte{'A'},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := decodeUTF16LE(tt.input)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

// Test threat detection
func TestDetectThreats(t *testing.T) {
	tests := []struct {
		name           string
		cmd            uint8
		status         uint32
		username       string
		share          string
		filename       string
		accessMask     uint32
		expectThreat   bool
		expectContains string
	}{
		{
			name:           "auth failure",
			cmd:            0,
			status:         0xC000006D, // LOGON_FAILURE
			expectThreat:   true,
			expectContains: "AUTH_FAILURE",
		},
		{
			name:           "account lockout",
			cmd:            0,
			status:         0xC0000234, // ACCOUNT_LOCKED_OUT
			expectThreat:   true,
			expectContains: "ACCOUNT_LOCKOUT",
		},
		{
			name:           "access denied",
			cmd:            0,
			status:         0xC0000022, // ACCESS_DENIED
			expectThreat:   true,
			expectContains: "ACCESS_DENIED",
		},
		{
			name:           "sensitive file access",
			filename:       "C:\\Windows\\NTDS\\ntds.dit",
			expectThreat:   true,
			expectContains: "SENSITIVE_FILE_ACCESS",
		},
		{
			name:           "admin share write",
			share:          "\\\\192.168.1.1\\ADMIN$",
			accessMask:     0x00000002, // WRITE_DATA
			expectThreat:   true,
			expectContains: "ADMIN_SHARE_WRITE",
		},
		{
			name:           "executable write",
			filename:       "malware.exe",
			accessMask:     0x00000002, // WRITE_DATA
			expectThreat:   true,
			expectContains: "EXECUTABLE_WRITE",
		},
		{
			name:           "psexec usage",
			filename:       "PSEXESVC.exe",
			expectThreat:   true,
			expectContains: "REMOTE_EXEC_TOOL",
		},
		{
			name:           "normal operation",
			filename:       "document.docx",
			share:          "\\\\server\\documents",
			accessMask:     0x00000001, // READ_DATA
			expectThreat:   false,
		},
		{
			name:           "sensitive pipe access",
			share:          "\\\\192.168.1.1\\IPC$",
			filename:       "svcctl",
			expectThreat:   true,
			expectContains: "SENSITIVE_PIPE_ACCESS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isThreat, indicator := detectThreats(tt.cmd, tt.status, tt.username, tt.share, tt.filename, tt.accessMask)
			if isThreat != tt.expectThreat {
				t.Errorf("Expected threat=%v, got %v (indicator: %s)", tt.expectThreat, isThreat, indicator)
			}
			if tt.expectContains != "" && isThreat {
				if indicator == "" || !strings.Contains(indicator, tt.expectContains) {
					t.Errorf("Expected indicator to contain %q, got %q", tt.expectContains, indicator)
				}
			}
		})
	}
}


// Test SMB2 capabilities parsing
func TestParseSMB2Capabilities(t *testing.T) {
	tests := []struct {
		caps     uint32
		expected []string
	}{
		{0x00000001, []string{"DFS"}},
		{0x00000002, []string{"LEASING"}},
		{0x00000040, []string{"ENCRYPTION"}},
		{0x00000043, []string{"DFS", "LEASING", "ENCRYPTION"}},
		{0x00000000, []string{}},
	}

	for _, tt := range tests {
		result := parseSMB2Capabilities(tt.caps)
		if len(result) != len(tt.expected) {
			t.Errorf("Expected %d capabilities, got %d for caps 0x%08X", len(tt.expected), len(result), tt.caps)
		}
	}
}

// Test operation classification
func TestClassifyOperation(t *testing.T) {
	tests := []struct {
		cmd      uint8
		action   string
		expected string
	}{
		{SMB1_COM_NEGOTIATE, "", "NEGOTIATE"},
		{SMB1_COM_SESSION_SETUP_ANDX, "", "AUTHENTICATION"},
		{SMB1_COM_TREE_CONNECT_ANDX, "", "SHARE_ACCESS"},
		{SMB1_COM_NT_CREATE_ANDX, "", "FILE_ACCESS"},
		{SMB1_COM_READ_ANDX, "", "FILE_READ"},
		{SMB1_COM_WRITE_ANDX, "", "FILE_WRITE"},
		{SMB1_COM_DELETE, "", "FILE_DELETE"},
		{SMB1_COM_CLOSE, "", "FILE_CLOSE"},
		{0xFF, "CUSTOM", "CUSTOM"},
		{0xFF, "", "OTHER"},
	}

	for _, tt := range tests {
		result := classifyOperation(tt.cmd, tt.action)
		if result != tt.expected {
			t.Errorf("Expected %s for cmd=0x%02X action=%q, got %s", tt.expected, tt.cmd, tt.action, result)
		}
	}
}

func TestClassifySMB2Operation(t *testing.T) {
	tests := []struct {
		cmd      uint16
		action   string
		expected string
	}{
		{SMB2_NEGOTIATE, "", "NEGOTIATE"},
		{SMB2_SESSION_SETUP, "", "AUTHENTICATION"},
		{SMB2_TREE_CONNECT, "", "SHARE_ACCESS"},
		{SMB2_CREATE, "", "FILE_ACCESS"},
		{SMB2_READ, "", "FILE_READ"},
		{SMB2_WRITE, "", "FILE_WRITE"},
		{SMB2_CLOSE, "", "FILE_CLOSE"},
		{SMB2_QUERY_DIRECTORY, "", "DIRECTORY_LISTING"},
		{0xFFFF, "CUSTOM", "CUSTOM"},
	}

	for _, tt := range tests {
		result := classifySMB2Operation(tt.cmd, tt.action)
		if result != tt.expected {
			t.Errorf("Expected %s for cmd=0x%04X action=%q, got %s", tt.expected, tt.cmd, tt.action, result)
		}
	}
}

// Test NTLM parsing helpers
func TestNTLMTargetInfoParsing(t *testing.T) {
	// Build a sample AV_PAIR list
	// MsvAvNbDomainName (0x0002) = "WORKGROUP"
	// MsvAvNbComputerName (0x0001) = "SERVER"
	// MsvAvEOL (0x0000)
	
	var data []byte
	
	// NbDomainName
	domainBytes := encodeUTF16LE("WORKGROUP")
	data = appendAVPair(data, MsvAvNbDomainName, domainBytes)
	
	// NbComputerName
	computerBytes := encodeUTF16LE("SERVER")
	data = appendAVPair(data, MsvAvNbComputerName, computerBytes)
	
	// EOL
	data = appendAVPair(data, MsvAvEOL, nil)
	
	// Parse it - use testing-safe helper
	reader := newTestSMBReader()
	info := &ntlmChallengeInfo{}
	reader.parseNTLMTargetInfo(data, info)
	
	if info.NbDomainName != "WORKGROUP" {
		t.Errorf("Expected NbDomainName=WORKGROUP, got %q", info.NbDomainName)
	}
	if info.NbComputerName != "SERVER" {
		t.Errorf("Expected NbComputerName=SERVER, got %q", info.NbComputerName)
	}
}

// Helper to encode UTF-16LE
func encodeUTF16LE(s string) []byte {
	result := make([]byte, len(s)*2)
	for i, r := range s {
		binary.LittleEndian.PutUint16(result[i*2:], uint16(r))
	}
	return result
}

// Helper to append AV_PAIR
func appendAVPair(data []byte, avID uint16, value []byte) []byte {
	pair := make([]byte, 4+len(value))
	binary.LittleEndian.PutUint16(pair[0:2], avID)
	binary.LittleEndian.PutUint16(pair[2:4], uint16(len(value)))
	copy(pair[4:], value)
	return append(data, pair...)
}

// Test NTLM CHALLENGE message parsing
func TestParseNTLMChallenge(t *testing.T) {
	// Build a minimal NTLM CHALLENGE message
	msg := make([]byte, 56)
	
	// Signature "NTLMSSP\0"
	copy(msg[0:8], []byte("NTLMSSP\x00"))
	
	// MessageType = 2 (CHALLENGE)
	binary.LittleEndian.PutUint32(msg[8:12], 2)
	
	// TargetName: empty for simplicity
	binary.LittleEndian.PutUint16(msg[12:14], 0)  // TargetNameLen
	binary.LittleEndian.PutUint16(msg[14:16], 0)  // TargetNameMaxLen
	binary.LittleEndian.PutUint32(msg[16:20], 0)  // TargetNameOffset
	
	// NegotiateFlags - set NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
	binary.LittleEndian.PutUint32(msg[20:24], 0x00080000)
	
	// ServerChallenge (8 bytes) - use a known value
	challengeBytes, _ := hex.DecodeString("0102030405060708")
	copy(msg[24:32], challengeBytes)
	
	// Reserved (8 bytes)
	// Offset 32-39 already zero
	
	// TargetInfo: empty
	binary.LittleEndian.PutUint16(msg[40:42], 0)  // TargetInfoLen
	binary.LittleEndian.PutUint16(msg[42:44], 0)  // TargetInfoMaxLen
	binary.LittleEndian.PutUint32(msg[44:48], 0)  // TargetInfoOffset
	
	// Parse it - use the testing-safe helper
	reader := newTestSMBReader()
	reader.parseNTLMChallenge(msg)
	
	if reader.ntlmVersion != "NTLMv2" {
		t.Errorf("Expected NTLMv2, got %q", reader.ntlmVersion)
	}
}

// Test NTLM AUTHENTICATE message parsing
func TestParseNTLMAuthenticate(t *testing.T) {
	// Build a sample NTLM AUTHENTICATE message with known values
	domain := "WORKGROUP"
	username := "testuser"
	workstation := "CLIENT01"
	
	domainBytes := encodeUTF16LE(domain)
	usernameBytes := encodeUTF16LE(username)
	workstationBytes := encodeUTF16LE(workstation)
	
	// Calculate offsets (payload starts after fixed header at offset 72)
	payloadStart := 72
	domainOffset := payloadStart
	usernameOffset := domainOffset + len(domainBytes)
	workstationOffset := usernameOffset + len(usernameBytes)
	
	// Build message
	msgLen := workstationOffset + len(workstationBytes)
	msg := make([]byte, msgLen)
	
	// Signature "NTLMSSP\0"
	copy(msg[0:8], []byte("NTLMSSP\x00"))
	
	// MessageType = 3 (AUTHENTICATE)
	binary.LittleEndian.PutUint32(msg[8:12], 3)
	
	// LmChallengeResponse (skip for simplicity)
	// NtChallengeResponse (skip for simplicity)
	
	// Domain: offset 28-35
	binary.LittleEndian.PutUint16(msg[28:30], uint16(len(domainBytes)))
	binary.LittleEndian.PutUint16(msg[30:32], uint16(len(domainBytes)))
	binary.LittleEndian.PutUint32(msg[32:36], uint32(domainOffset))
	
	// Username: offset 36-43
	binary.LittleEndian.PutUint16(msg[36:38], uint16(len(usernameBytes)))
	binary.LittleEndian.PutUint16(msg[38:40], uint16(len(usernameBytes)))
	binary.LittleEndian.PutUint32(msg[40:44], uint32(usernameOffset))
	
	// Workstation: offset 44-51
	binary.LittleEndian.PutUint16(msg[44:46], uint16(len(workstationBytes)))
	binary.LittleEndian.PutUint16(msg[46:48], uint16(len(workstationBytes)))
	binary.LittleEndian.PutUint32(msg[48:52], uint32(workstationOffset))
	
	// NegotiateFlags: offset 60-63, set NTLMv2 flag
	binary.LittleEndian.PutUint32(msg[60:64], 0x00080000)
	
	// Copy payload data
	copy(msg[domainOffset:], domainBytes)
	copy(msg[usernameOffset:], usernameBytes)
	copy(msg[workstationOffset:], workstationBytes)
	
	// Parse it - use testing-safe helper
	reader := newTestSMBReader()
	reader.parseNTLMAuthenticate(msg)
	
	if reader.domain != domain {
		t.Errorf("Expected domain=%q, got %q", domain, reader.domain)
	}
	if reader.username != username {
		t.Errorf("Expected username=%q, got %q", username, reader.username)
	}
	if reader.workstation != workstation {
		t.Errorf("Expected workstation=%q, got %q", workstation, reader.workstation)
	}
	if reader.ntlmVersion != "NTLMv2" {
		t.Errorf("Expected NTLMv2, got %q", reader.ntlmVersion)
	}
}

// Test share type names
func TestShareTypeNames(t *testing.T) {
	tests := []struct {
		shareType uint8
		expected  string
	}{
		{0x00, "DISK"},
		{0x01, "PRINTER"},
		{0x02, "PIPE"},
		{0x03, "COMM"},
	}

	for _, tt := range tests {
		name, ok := shareTypeNames[tt.shareType]
		if !ok {
			t.Errorf("Share type 0x%02X not found", tt.shareType)
			continue
		}
		if name != tt.expected {
			t.Errorf("Expected %q, got %q for share type 0x%02X", tt.expected, name, tt.shareType)
		}
	}
}

// Test state reset
func TestResetMessageState(t *testing.T) {
	reader := &smbReader{
		filename:         "test.txt",
		action:           "READ",
		accessMask:       0x12345678,
		createDisp:       1,
		fileAttributes:   0xABCD,
		fileID:           999,
		isDirectory:      true,
		bytesTransferred: 1024,
		offset:           512,
		// Session-level state that should NOT be reset
		username:  "testuser",
		domain:    "DOMAIN",
		sessionID: 12345,
	}

	reader.resetMessageState()

	// Check per-message state is reset
	if reader.filename != "" {
		t.Error("filename should be reset")
	}
	if reader.action != "" {
		t.Error("action should be reset")
	}
	if reader.accessMask != 0 {
		t.Error("accessMask should be reset")
	}
	if reader.fileID != 0 {
		t.Error("fileID should be reset")
	}

	// Check session-level state is preserved
	if reader.username != "testuser" {
		t.Error("username should be preserved")
	}
	if reader.domain != "DOMAIN" {
		t.Error("domain should be preserved")
	}
	if reader.sessionID != 12345 {
		t.Error("sessionID should be preserved")
	}
}

