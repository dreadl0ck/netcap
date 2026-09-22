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

// Package quic implements QUIC protocol analysis for both gQUIC and IETF QUIC.
// The gQUIC parsing is based on patterns from https://github.com/0x4D31/quick
package quic

import (
	"encoding/binary"
	"strings"

	"go.uber.org/zap"
)

// gQUIC constants
const (
	// CHLO message tag
	gquicTagCHLO = "CHLO"

	// Known CHLO tags
	gquicTagSNI  = "SNI\x00" // Server Name Indication
	gquicTagUAID = "UAID"    // User Agent ID
	gquicTagVER  = "VER\x00" // Version
	gquicTagPAD  = "PAD\x00" // Padding
	gquicTagSTK  = "STK\x00" // Source Token
	gquicTagCCS  = "CCS\x00" // Common Certificate Sets
	gquicTagNONC = "NONC"    // Client Nonce
	gquicTagAEAD = "AEAD"    // AEAD algorithm
	gquicTagSCID = "SCID"    // Server Config ID
	gquicTagTCID = "TCID"    // Truncated Connection ID
	gquicTagPDMD = "PDMD"    // Proof Demand
	gquicTagSMHL = "SMHL"    // Server Max Header List Size
	gquicTagICSL = "ICSL"    // Idle Connection State Lifetime
	gquicTagNONP = "NONP"    // Client Nonce Proof
	gquicTagPUBS = "PUBS"    // Public Value
	gquicTagMIDS = "MIDS"    // Max Incoming Dynamic Streams
	gquicTagSCLS = "SCLS"    // Session Cache Life Span
	gquicTagKEXS = "KEXS"    // Key Exchange Algorithms
	gquicTagXLCT = "XLCT"    // Expected Leaf Certificate
	gquicTagCSCT = "CSCT"    // Certificate Timestamp
	gquicTagCOPT = "COPT"    // Connection Options
	gquicTagCCRT = "CCRT"    // Client Cert
	gquicTagIRTT = "IRTT"    // Initial Round Trip Time
	gquicTagCFCW = "CFCW"    // Connection Flow Control Window
	gquicTagSFCW = "SFCW"    // Stream Flow Control Window
)

// GQUICClientHello represents parsed gQUIC CHLO data.
type GQUICClientHello struct {
	Version    string            // QUIC version (e.g., "Q043", "Q046")
	CID        []byte            // Connection ID (8 bytes for gQUIC)
	SNI        string            // Server Name Indication
	UAID       string            // User Agent ID (e.g., "Chrome/74.0.3729.131 Intel Mac OS X 10_14_4")
	Tags       []string          // Tags in order for fingerprinting
	TagValues  map[string]string // Tag values
	PacketNum  int               // Packet number
	FrameType  byte              // Frame type
	StreamID   int               // Stream ID
	DataLength int               // Data length
	RawMAC     []byte            // Message Authentication Hash
}

// ParseGQUICClientHello parses a gQUIC packet and extracts CHLO information.
// Based on patterns from https://github.com/0x4D31/quick
//
// gQUIC versions (Q043, Q044, Q046, Q050) use a different packet format than IETF QUIC.
// The format consists of:
// - Public Flags (1 byte)
// - Connection ID (8 bytes, optional based on flags)
// - Version (4 bytes, optional based on flags)
// - Packet Number (1-6 bytes based on flags)
// - Payload containing CHLO message
func ParseGQUICClientHello(payload []byte) (*GQUICClientHello, error) {
	if len(payload) < 15 {
		return nil, nil
	}

	chlo := &GQUICClientHello{
		TagValues: make(map[string]string),
	}

	offset := 0

	// Parse Public Flags (1 byte)
	// Bit 0x01: Version present (for client->server, indicates client version)
	// Bit 0x08: Connection ID present (8 bytes)
	// Bits 0x30: Packet number length encoding
	publicFlags := payload[offset]
	offset++

	// Parse Connection ID if present (flags bit 0x08)
	if publicFlags&0x08 != 0 {
		if offset+8 > len(payload) {
			return nil, nil
		}
		chlo.CID = make([]byte, 8)
		copy(chlo.CID, payload[offset:offset+8])
		offset += 8
	}

	// Parse Version if present (flags bit 0x01)
	if publicFlags&0x01 != 0 {
		if offset+4 > len(payload) {
			return nil, nil
		}
		chlo.Version = string(payload[offset : offset+4])
		offset += 4
	}

	// Parse Packet Number (1-6 bytes based on flags)
	// Bits 4-5 encode the packet number length:
	// 00 = 1 byte, 01 = 2 bytes, 10 = 4 bytes, 11 = 6 bytes
	pnLenCode := (publicFlags & 0x30) >> 4
	var pnLen int
	switch pnLenCode {
	case 0:
		pnLen = 1
	case 1:
		pnLen = 2
	case 2:
		pnLen = 4
	case 3:
		pnLen = 6
	}
	if offset+pnLen > len(payload) {
		return nil, nil
	}
	chlo.PacketNum = int(parsePacketNumber(payload[offset:offset+pnLen], pnLen))
	offset += pnLen

	// Note: The MAC/hash handling differs between encrypted and unencrypted packets.
	// For CHLO packets (which are unencrypted), there's no hash here.
	// We skip directly to looking for the STREAM frame.

	// Look for STREAM frame with CHLO
	if offset >= len(payload) {
		return nil, nil
	}

	// Frame Type (typically 0xa0 for STREAM frame)
	chlo.FrameType = payload[offset]
	offset++

	// For STREAM frames (0xa0 - 0xbf range)
	if chlo.FrameType >= 0xa0 && chlo.FrameType <= 0xbf {
		// Parse Stream ID (variable length based on frame type bits)
		streamIDLen := 1
		if chlo.FrameType&0x0c != 0 {
			streamIDLen = int((chlo.FrameType&0x0c)>>2) + 1
		}
		if offset+streamIDLen > len(payload) {
			return nil, nil
		}
		chlo.StreamID = int(parsePacketNumber(payload[offset:offset+streamIDLen], streamIDLen))
		offset += streamIDLen

		// Parse Offset if present (frame type bit 0x01)
		if chlo.FrameType&0x01 != 0 {
			offsetLen := int((chlo.FrameType&0x1c)>>2) + 1
			if offset+offsetLen > len(payload) {
				return nil, nil
			}
			offset += offsetLen // Skip offset for now
		}

		// Parse Data Length if present (frame type bit 0x02)
		if chlo.FrameType&0x02 != 0 {
			if offset+2 > len(payload) {
				return nil, nil
			}
			chlo.DataLength = int(binary.LittleEndian.Uint16(payload[offset : offset+2]))
			offset += 2
		}
	}

	// Parse CHLO message
	return parseCHLO(payload, offset, chlo)
}

// parseCHLO parses the CHLO message from the payload.
func parseCHLO(payload []byte, offset int, chlo *GQUICClientHello) (*GQUICClientHello, error) {
	// Look for CHLO tag
	chloOffset := findCHLOTag(payload[offset:])
	if chloOffset < 0 {
		return nil, nil
	}
	offset += chloOffset

	// Verify CHLO tag
	if offset+4 > len(payload) {
		return nil, nil
	}
	if string(payload[offset:offset+4]) != gquicTagCHLO {
		return nil, nil
	}
	offset += 4

	// Number of tags (2 bytes, little endian)
	if offset+2 > len(payload) {
		return nil, nil
	}
	numTags := int(binary.LittleEndian.Uint16(payload[offset : offset+2]))
	offset += 2

	// Padding (2 bytes)
	if offset+2 > len(payload) {
		return nil, nil
	}
	offset += 2

	// Parse tag-offset pairs
	tagStart := offset + (numTags * 8)
	if tagStart > len(payload) {
		return nil, nil
	}

	// Read tag information
	type tagInfo struct {
		name   string
		offset int
	}
	tags := make([]tagInfo, numTags)
	prevOffset := 0

	for i := range numTags {
		if offset+8 > len(payload) {
			break
		}

		// Tag name (4 bytes)
		tagName := string(payload[offset : offset+4])
		offset += 4

		// Tag end offset (4 bytes, little endian)
		endOffset := int(binary.LittleEndian.Uint32(payload[offset : offset+4]))
		offset += 4

		tags[i] = tagInfo{
			name:   tagName,
			offset: endOffset,
		}

		// Track tag order for fingerprinting
		cleanName := strings.TrimRight(tagName, "\x00")
		chlo.Tags = append(chlo.Tags, cleanName)

		prevOffset = endOffset
		_ = prevOffset
	}

	// Parse tag values
	valuesStart := offset
	prevOffset = 0

	for _, tag := range tags {
		if tag.name == "" {
			continue
		}

		valueStart := valuesStart + prevOffset
		valueEnd := valuesStart + tag.offset

		if valueStart >= len(payload) || valueEnd > len(payload) || valueStart > valueEnd {
			break
		}

		value := payload[valueStart:valueEnd]
		cleanName := strings.TrimRight(tag.name, "\x00")

		// Store raw value as string (may need hex encoding for binary values)
		switch cleanName {
		case "SNI":
			chlo.SNI = string(value)
			chlo.TagValues[cleanName] = string(value)
		case "UAID":
			chlo.UAID = string(value)
			chlo.TagValues[cleanName] = string(value)
		case "VER":
			chlo.TagValues[cleanName] = string(value)
		case "AEAD", "KEXS":
			// These are typically 4-byte codes
			chlo.TagValues[cleanName] = string(value)
		case "PAD":
			// Skip padding
		default:
			// Store as hex for binary data
			if isPrintable(value) {
				chlo.TagValues[cleanName] = string(value)
			} else {
				chlo.TagValues[cleanName] = bytesToHex(value)
			}
		}

		prevOffset = tag.offset
	}

	return chlo, nil
}

// findCHLOTag searches for the CHLO tag in the payload.
func findCHLOTag(data []byte) int {
	for i := 0; i < len(data)-4; i++ {
		if string(data[i:i+4]) == gquicTagCHLO {
			return i
		}
	}
	return -1
}

// parsePacketNumber parses a packet number from bytes.
func parsePacketNumber(data []byte, length int) uint64 {
	var result uint64
	for i := 0; i < length && i < len(data); i++ {
		result |= uint64(data[i]) << (8 * i)
	}
	return result
}

// isPrintable checks if all bytes in the slice are printable ASCII.
func isPrintable(data []byte) bool {
	for _, b := range data {
		if b < 0x20 || b > 0x7e {
			return false
		}
	}
	return true
}

// bytesToHex converts bytes to a hex string.
func bytesToHex(data []byte) string {
	const hexDigits = "0123456789abcdef"
	result := make([]byte, len(data)*2)
	for i, b := range data {
		result[i*2] = hexDigits[b>>4]
		result[i*2+1] = hexDigits[b&0x0f]
	}
	return string(result)
}

// IsGQUICPacket checks if the payload looks like a gQUIC packet.
// gQUIC packets can have two forms:
// 1. Long form with version (handshake): contains "Qxxx" version string
// 2. Short form without version (after handshake): identified by public flags pattern
func IsGQUICPacket(payload []byte) bool {
	if len(payload) < 5 {
		return false
	}

	// Check for gQUIC version string (starts with 'Q' followed by 3 digits)
	// Version is at different offsets depending on public flags
	for i := 1; i <= 9 && i+4 <= len(payload); i++ {
		if payload[i] == 'Q' && isDigit(payload[i+1]) && isDigit(payload[i+2]) && isDigit(payload[i+3]) {
			return true
		}
	}

	// Check for gQUIC short header pattern (post-handshake packets)
	// These don't have version, but have specific public flags patterns
	// Public flags byte structure:
	// - Bit 0x08: Connection ID present (8 bytes)
	// - Bit 0x01: Version present (only in handshake)
	// - Bits 0x30: Packet number length (00=1, 01=2, 10=4, 11=6 bytes)
	// - Bit 0x04: Reset flag
	// - Bit 0x02: Nonce present
	// For data packets after handshake: typically 0x08, 0x0c, 0x18, 0x1c, etc.
	publicFlags := payload[0]

	// gQUIC short header with CID (most common case)
	if (publicFlags&0x08 != 0) && (publicFlags&0x01 == 0) {
		// Has connection ID, no version - likely gQUIC data packet
		// Additional check: high bits should be 0 (bits 5-7 are reserved/unused)
		if publicFlags&0xe0 == 0 {
			// Must have at least: 1 (flags) + 8 (CID) + 1 (packet number) = 10 bytes
			if len(payload) >= 10 {
				return true
			}
		}
	}

	// Note: We intentionally don't detect gQUIC without CID (truncated CID mode)
	// because it would cause too many false positives on random UDP traffic.
	// Most gQUIC traffic uses 8-byte connection IDs.

	return false
}

func isDigit(b byte) bool {
	return b >= '0' && b <= '9'
}

// logGQUICParsing logs gQUIC parsing activity (used for debugging).
func logGQUICParsing(log *zap.Logger, msg string, fields ...zap.Field) {
	if log != nil {
		log.Debug(msg, fields...)
	}
}
