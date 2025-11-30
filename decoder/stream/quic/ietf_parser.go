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

package quic

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"

	"golang.org/x/crypto/hkdf"
	"crypto/sha256"
	"io"
)

// IETF QUIC constants
const (
	// QUIC versions
	quicVersionIETF1 uint32 = 0x00000001
	quicVersionIETF2 uint32 = 0x6b3343cf

	// Initial salt for QUIC v1 (RFC 9001)
	// Used to derive the initial secret from the DCID
)

// Initial salt for QUIC v1 (RFC 9001 Section 5.2)
var quicV1InitialSalt = []byte{
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
	0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
	0xcc, 0xbb, 0x7f, 0x0a,
}

// Initial salt for QUIC v2 (RFC 9369)
var quicV2InitialSalt = []byte{
	0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb,
	0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
	0xf9, 0xbd, 0x2e, 0xd9,
}

// Initial salt for QUIC draft-29 (draft-ietf-quic-tls-29)
// Used for version 0xff00001d
var quicDraft29Salt = []byte{
	0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c,
	0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0,
	0x43, 0x90, 0xa8, 0x99,
}

// Initial salt for QUIC draft-23 through draft-28
// Used for versions 0xff000017 through 0xff00001c
var quicDraft23Salt = []byte{
	0xc3, 0xee, 0xf7, 0x12, 0xc7, 0x2e, 0xbb, 0x5a,
	0x11, 0xa7, 0xd2, 0x43, 0x2b, 0xb4, 0x63, 0x65,
	0xbe, 0xf9, 0xf5, 0x02,
}

// Initial salt for QUIC draft-22
// Used for version 0xff000016
var quicDraft22Salt = []byte{
	0x7f, 0xbc, 0xdb, 0x0e, 0x7c, 0x66, 0xbb, 0xe9,
	0x19, 0x3a, 0x96, 0xcd, 0x21, 0x51, 0x9e, 0xbd,
	0x7a, 0x02, 0x64, 0x4a,
}

// Initial salt for QUIC draft-17 through draft-21
// Used for versions 0xff000011 through 0xff000015
var quicDraft17Salt = []byte{
	0xef, 0x4f, 0xb0, 0xab, 0xb4, 0x74, 0x70, 0xc4,
	0x1b, 0xef, 0xcf, 0x80, 0x31, 0x33, 0x4f, 0xae,
	0x48, 0x5e, 0x09, 0xa0,
}

// Initial salt for QUIC draft-14 through draft-16
// Used for versions 0xff00000e through 0xff000010
var quicDraft14Salt = []byte{
	0x9c, 0x10, 0x8f, 0x98, 0x52, 0x0a, 0x5c, 0x5c,
	0x32, 0x96, 0x8e, 0x95, 0x0e, 0x8a, 0x2c, 0x5f,
	0xe0, 0x6d, 0x6c, 0x38,
}

// Initial salt for QUIC draft-13 and earlier (draft-11 through draft-13)
// Used for versions 0xff00000b through 0xff00000d
var quicDraft11Salt = []byte{
	0xaf, 0xc8, 0x24, 0xec, 0x63, 0x15, 0x49, 0xe5,
	0x2b, 0xfe, 0x3e, 0x7d, 0xfd, 0xa4, 0x8f, 0xb4,
	0xe8, 0xcd, 0x2b, 0x32,
}

// HKDF labels for QUIC (RFC 9001)
var (
	clientInLabel = []byte("client in")
	quicKeyLabel  = []byte("quic key")
	quicIVLabel   = []byte("quic iv")
	quicHPLabel   = []byte("quic hp")
)

// getSaltForVersion returns the appropriate initial salt for a QUIC version.
// Different QUIC draft versions used different initial salts.
// See: https://github.com/quicwg/base-drafts/wiki/Versions
func getSaltForVersion(version uint32) []byte {
	switch version {
	// RFC versions
	case quicVersionIETF1: // QUIC v1 (0x00000001) - RFC 9001
		return quicV1InitialSalt
	case quicVersionIETF2: // QUIC v2 (0x6b3343cf) - RFC 9369
		return quicV2InitialSalt

	// Draft-29 (final draft before RFC)
	case 0xff00001d: // draft-29
		return quicDraft29Salt

	// Draft-23 through draft-28
	case 0xff00001c: // draft-28
		return quicDraft23Salt
	case 0xff00001b: // draft-27
		return quicDraft23Salt
	case 0xff00001a: // draft-26
		return quicDraft23Salt
	case 0xff000019: // draft-25
		return quicDraft23Salt
	case 0xff000018: // draft-24
		return quicDraft23Salt
	case 0xff000017: // draft-23
		return quicDraft23Salt

	// Draft-22
	case 0xff000016: // draft-22
		return quicDraft22Salt

	// Draft-17 through draft-21
	case 0xff000015: // draft-21
		return quicDraft17Salt
	case 0xff000014: // draft-20
		return quicDraft17Salt
	case 0xff000013: // draft-19
		return quicDraft17Salt
	case 0xff000012: // draft-18
		return quicDraft17Salt
	case 0xff000011: // draft-17
		return quicDraft17Salt

	// Draft-14 through draft-16
	case 0xff000010: // draft-16
		return quicDraft14Salt
	case 0xff00000f: // draft-15
		return quicDraft14Salt
	case 0xff00000e: // draft-14
		return quicDraft14Salt

	// Draft-11 through draft-13
	case 0xff00000d: // draft-13
		return quicDraft11Salt
	case 0xff00000c: // draft-12
		return quicDraft11Salt
	case 0xff00000b: // draft-11
		return quicDraft11Salt

	default:
		// For unknown draft versions, try to guess based on range
		if version >= 0xff000000 {
			draftNum := version & 0x000000ff
			if draftNum >= 29 {
				return quicDraft29Salt
			} else if draftNum >= 23 {
				return quicDraft23Salt
			} else if draftNum >= 17 {
				return quicDraft17Salt
			} else if draftNum >= 14 {
				return quicDraft14Salt
			} else if draftNum >= 11 {
				return quicDraft11Salt
			}
		}
		// Unknown version - return nil to indicate we can't decrypt
		return nil
	}
}

// IETFQUICClientHello represents parsed IETF QUIC Initial packet data.
type IETFQUICClientHello struct {
	Version           uint32 // QUIC version
	DCID              []byte // Destination Connection ID
	SCID              []byte // Source Connection ID
	Token             []byte // Token (for address validation)
	PacketNumber      int64
	
	// Embedded TLS ClientHello data
	TLSVersion        uint16   // TLS version from ClientHello
	Random            []byte   // TLS random (32 bytes)
	SessionID         []byte   // Session ID
	CipherSuites      []uint16 // Cipher suites offered
	CompressionMethods []byte  // Compression methods
	Extensions        []uint16 // Extension types
	SNI               string   // Server Name Indication
	ALPNs             []string // ALPN protocols
	SupportedGroups   []uint16 // Supported elliptic curves
	SignatureAlgs     []uint16 // Signature algorithms
	SupportedVersions []uint16 // TLS supported versions extension
	
	// QUIC Transport Parameters (RFC 9000 Section 18.2)
	// Extension type: 0x39 for QUIC v1 (RFC 9001), 0x57 for QUIC v2 (RFC 9369)
	MaxIdleTimeout               uint64  // 0x01
	MaxUDPPayloadSize            uint64  // 0x03
	InitialMaxData               uint64  // 0x04
	InitialMaxStreamDataBidiLocal uint64 // 0x05
	InitialMaxStreamDataBidiRemote uint64 // 0x06
	InitialMaxStreamDataUni      uint64  // 0x07
	InitialMaxStreamsBidi        uint64  // 0x08
	InitialMaxStreamsUni         uint64  // 0x09
	AckDelayExponent             uint64  // 0x0a (default: 3)
	MaxAckDelay                  uint64  // 0x0b (default: 25ms)
	DisableActiveMigration       bool    // 0x0c
	ActiveConnectionIDLimit      uint64  // 0x0e (default: 2)
	InitialSourceConnectionID    []byte  // 0x0f
}

// ParseIETFQUICInitial parses an IETF QUIC Initial packet and extracts the ClientHello.
// This requires decrypting the packet header and payload using the Initial secret.
func ParseIETFQUICInitial(payload []byte) (*IETFQUICClientHello, error) {
	if len(payload) < 7 {
		return nil, nil
	}

	// Check for long header
	if payload[0]&0x80 == 0 {
		return nil, nil // Short header, not Initial
	}

	// Check header type (bits 4-5)
	// RFC 9000 (QUIC v1): Initial=0, 0-RTT=1, Handshake=2, Retry=3
	// RFC 9369 (QUIC v2): Initial=1, 0-RTT=2, Handshake=3, Retry=0 (swapped!)
	headerType := (payload[0] & 0x30) >> 4
	
	// We need to peek at the version first to determine header type mapping
	if len(payload) < 5 {
		return nil, nil
	}
	peekVersion := binary.BigEndian.Uint32(payload[1:5])
	
	// For QUIC v1 (0x00000001): Initial = 0
	// For QUIC v2 (0x6b3343cf): Initial = 1
	isInitial := false
	if peekVersion == quicVersionIETF1 {
		isInitial = (headerType == 0)
	} else if peekVersion == quicVersionIETF2 {
		isInitial = (headerType == 1)
	} else if peekVersion >= 0xff000000 && peekVersion <= 0xff00001d {
		// Draft versions use v1 encoding
		isInitial = (headerType == 0)
	}
	
	if !isInitial {
		return nil, nil // Not an Initial packet
	}

	result := &IETFQUICClientHello{}
	offset := 1

	// Parse version (4 bytes)
	if offset+4 > len(payload) {
		return nil, nil
	}
	result.Version = binary.BigEndian.Uint32(payload[offset : offset+4])
	offset += 4

	// Validate version
	if result.Version != quicVersionIETF1 && result.Version != quicVersionIETF2 {
		// Check for draft versions
		if result.Version < 0xff000000 || result.Version > 0xff00001d {
			return nil, nil
		}
	}

	// Parse DCID length and DCID
	if offset >= len(payload) {
		return nil, nil
	}
	dcidLen := int(payload[offset])
	offset++
	if dcidLen > 20 || offset+dcidLen > len(payload) {
		return nil, nil
	}
	result.DCID = make([]byte, dcidLen)
	copy(result.DCID, payload[offset:offset+dcidLen])
	offset += dcidLen

	// Parse SCID length and SCID
	if offset >= len(payload) {
		return nil, nil
	}
	scidLen := int(payload[offset])
	offset++
	if scidLen > 20 || offset+scidLen > len(payload) {
		return nil, nil
	}
	result.SCID = make([]byte, scidLen)
	copy(result.SCID, payload[offset:offset+scidLen])
	offset += scidLen

	// Parse token length (variable-length integer)
	tokenLen, bytesRead := parseQUICVarint(payload[offset:])
	if bytesRead == 0 {
		return nil, nil
	}
	offset += bytesRead

	// Parse token
	if tokenLen > 0 {
		if offset+int(tokenLen) > len(payload) {
			return nil, nil
		}
		result.Token = make([]byte, tokenLen)
		copy(result.Token, payload[offset:offset+int(tokenLen)])
		offset += int(tokenLen)
	}

	// Parse length (variable-length integer)
	length, bytesRead := parseQUICVarint(payload[offset:])
	if bytesRead == 0 {
		return nil, nil
	}
	offset += bytesRead

	// The remaining payload is encrypted
	// To decrypt, we need to derive the Initial secret from the DCID
	encryptedPayload := payload[offset:]
	if len(encryptedPayload) < int(length) || len(encryptedPayload) < 4 {
		return nil, nil
	}

	// Derive Initial secret and attempt decryption
	clientHello, err := decryptInitialPacket(result, payload, offset, int(length))
	if err != nil || clientHello == nil {
		// Even if decryption fails, we still have header info
		return result, nil
	}

	return clientHello, nil
}

// decryptInitialPacket attempts to decrypt an IETF QUIC Initial packet.
// Returns the result with TLS ClientHello data if successful.
func decryptInitialPacket(result *IETFQUICClientHello, fullPacket []byte, payloadOffset, length int) (*IETFQUICClientHello, error) {
	// Select the appropriate salt based on version
	salt := getSaltForVersion(result.Version)
	if salt == nil {
		return result, nil // Unknown version
	}

	// Derive initial secret from DCID (RFC 9001 Section 5.2)
	initialSecret := hkdfExtract(salt, result.DCID)
	
	// Derive client initial secret
	clientSecret := hkdfExpandLabel(initialSecret, clientInLabel, nil, 32)
	
	// Derive key and IV
	key := hkdfExpandLabel(clientSecret, quicKeyLabel, nil, 16)
	iv := hkdfExpandLabel(clientSecret, quicIVLabel, nil, 12)
	hp := hkdfExpandLabel(clientSecret, quicHPLabel, nil, 16)

	// Remove header protection to get packet number
	pnOffset := payloadOffset
	if len(fullPacket) < pnOffset+4+16 {
		return result, nil
	}

	// Sample for header protection (16 bytes starting 4 bytes after pn_offset)
	sampleOffset := pnOffset + 4
	if sampleOffset+16 > len(fullPacket) {
		return result, nil
	}
	sample := fullPacket[sampleOffset : sampleOffset+16]

	// Create AES block cipher for header protection
	hpBlock, err := aes.NewCipher(hp)
	if err != nil {
		return result, nil
	}

	// Generate mask using AES-ECB
	mask := make([]byte, 16)
	hpBlock.Encrypt(mask, sample)

	// Remove header protection from first byte and packet number
	header := make([]byte, len(fullPacket))
	copy(header, fullPacket)
	
	// Unprotect the first byte
	header[0] ^= mask[0] & 0x0f // Low 4 bits for long header

	// Determine packet number length from unprotected first byte
	pnLen := int(header[0]&0x03) + 1

	// Unprotect packet number bytes
	for i := 0; i < pnLen; i++ {
		header[pnOffset+i] ^= mask[1+i]
	}

	// Extract packet number
	var packetNumber int64
	for i := 0; i < pnLen; i++ {
		packetNumber = (packetNumber << 8) | int64(header[pnOffset+i])
	}
	result.PacketNumber = packetNumber

	// Prepare AAD (additional authenticated data) = header up to and including packet number
	aadLen := pnOffset + pnLen
	if aadLen > len(header) {
		return result, nil
	}
	aad := header[:aadLen]

	// Prepare nonce
	nonce := make([]byte, 12)
	copy(nonce, iv)
	// XOR packet number into last bytes of nonce
	for i := 0; i < 8; i++ {
		nonce[11-i] ^= byte(packetNumber >> (8 * i))
	}

	// Decrypt payload
	ciphertext := fullPacket[aadLen : payloadOffset+length]
	if len(ciphertext) < 16 { // Need at least tag length
		return result, nil
	}

	aesgcm, err := cipher.NewGCM(func() cipher.Block {
		block, _ := aes.NewCipher(key)
		return block
	}())
	if err != nil {
		return result, nil
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		// Decryption failed - this is common for non-Initial packets or malformed data
		return result, nil
	}

	// Parse decrypted frames for CRYPTO frame containing ClientHello
	parseCryptoFrames(plaintext, result)

	return result, nil
}

// cryptoFragment represents a fragment of CRYPTO frame data.
type cryptoFragment struct {
	offset uint64
	data   []byte
}

// parseCryptoFrames parses QUIC frames looking for CRYPTO frames with TLS data.
// It handles fragmented and out-of-order CRYPTO frames by reassembling them.
func parseCryptoFrames(data []byte, result *IETFQUICClientHello) {
	// Collect all CRYPTO fragments
	var fragments []cryptoFragment
	offset := 0

	for offset < len(data) {
		frameType := data[offset]
		offset++

		switch frameType {
		case 0x00: // PADDING
			// Skip consecutive padding frames
			for offset < len(data) && data[offset] == 0x00 {
				offset++
			}
			continue
		case 0x01: // PING
			continue
		case 0x02, 0x03: // ACK frames - skip them
			// ACK frame has variable structure, skip for now
			// This shouldn't appear in Initial packets, but handle gracefully
			return
		case 0x06: // CRYPTO frame
			// Parse crypto frame offset
			cryptoOffset, bytesRead := parseQUICVarint(data[offset:])
			if bytesRead == 0 {
				return
			}
			offset += bytesRead

			// Parse crypto frame length
			cryptoLength, bytesRead := parseQUICVarint(data[offset:])
			if bytesRead == 0 {
				return
			}
			offset += bytesRead

			if offset+int(cryptoLength) > len(data) {
				return
			}

			// Store this fragment
			fragData := make([]byte, cryptoLength)
			copy(fragData, data[offset:offset+int(cryptoLength)])
			fragments = append(fragments, cryptoFragment{
				offset: cryptoOffset,
				data:   fragData,
			})
			offset += int(cryptoLength)
		default:
			// Unknown frame type - stop parsing
			// but try to reassemble what we have
			break
		}
	}

	if len(fragments) == 0 {
		return
	}

	// Reassemble CRYPTO fragments
	tlsData := reassembleCryptoFragments(fragments)
	if len(tlsData) > 0 {
		parseTLSClientHello(tlsData, result)
	}
}

// reassembleCryptoFragments reassembles CRYPTO fragments into a contiguous buffer.
// Fragments may be out of order or overlapping.
func reassembleCryptoFragments(fragments []cryptoFragment) []byte {
	if len(fragments) == 0 {
		return nil
	}

	// Find the total size needed
	var maxEnd uint64
	for _, frag := range fragments {
		end := frag.offset + uint64(len(frag.data))
		if end > maxEnd {
			maxEnd = end
		}
	}

	// Sanity check - don't allocate huge buffers
	if maxEnd > 65536 {
		return nil
	}

	// Create reassembly buffer
	buffer := make([]byte, maxEnd)

	// Copy fragments into buffer
	for _, frag := range fragments {
		copy(buffer[frag.offset:], frag.data)
	}

	return buffer
}

// parseTLSClientHello parses a TLS 1.3 ClientHello message.
func parseTLSClientHello(data []byte, result *IETFQUICClientHello) {
	if len(data) < 6 {
		return
	}

	// TLS handshake type (1 byte) - should be 0x01 for ClientHello
	if data[0] != 0x01 {
		return
	}

	// Length (3 bytes)
	length := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if len(data) < 4+length {
		return
	}

	offset := 4

	// Client version (2 bytes)
	if offset+2 > len(data) {
		return
	}
	result.TLSVersion = binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	// Random (32 bytes)
	if offset+32 > len(data) {
		return
	}
	result.Random = make([]byte, 32)
	copy(result.Random, data[offset:offset+32])
	offset += 32

	// Session ID length (1 byte) + Session ID
	if offset >= len(data) {
		return
	}
	sessionIDLen := int(data[offset])
	offset++
	if offset+sessionIDLen > len(data) {
		return
	}
	if sessionIDLen > 0 {
		result.SessionID = make([]byte, sessionIDLen)
		copy(result.SessionID, data[offset:offset+sessionIDLen])
	}
	offset += sessionIDLen

	// Cipher Suites length (2 bytes) + Cipher Suites
	if offset+2 > len(data) {
		return
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2
	if offset+cipherSuitesLen > len(data) {
		return
	}
	numCipherSuites := cipherSuitesLen / 2
	result.CipherSuites = make([]uint16, numCipherSuites)
	for i := 0; i < numCipherSuites; i++ {
		result.CipherSuites[i] = binary.BigEndian.Uint16(data[offset : offset+2])
		offset += 2
	}

	// Compression Methods length (1 byte) + Compression Methods
	if offset >= len(data) {
		return
	}
	compressionLen := int(data[offset])
	offset++
	if offset+compressionLen > len(data) {
		return
	}
	result.CompressionMethods = make([]byte, compressionLen)
	copy(result.CompressionMethods, data[offset:offset+compressionLen])
	offset += compressionLen

	// Extensions length (2 bytes) + Extensions
	if offset+2 > len(data) {
		return
	}
	extensionsLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2
	if offset+extensionsLen > len(data) {
		return
	}

	// Parse extensions
	extEnd := offset + extensionsLen
	for offset < extEnd {
		if offset+4 > len(data) {
			break
		}

		extType := binary.BigEndian.Uint16(data[offset : offset+2])
		offset += 2
		extLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
		offset += 2

		if offset+extLen > len(data) {
			break
		}

		extData := data[offset : offset+extLen]
		result.Extensions = append(result.Extensions, extType)

		switch extType {
		case 0x0000: // server_name (SNI)
			result.SNI = parseSNIExtension(extData)
		case 0x0010: // application_layer_protocol_negotiation (ALPN)
			result.ALPNs = parseALPNExtension(extData)
		case 0x000a: // supported_groups
			result.SupportedGroups = parseSupportedGroups(extData)
		case 0x000d: // signature_algorithms
			result.SignatureAlgs = parseSignatureAlgs(extData)
		case 0x002b: // supported_versions
			result.SupportedVersions = parseSupportedVersions(extData)
		case 0x0039: // quic_transport_parameters (QUIC v1, RFC 9001)
			parseQUICTransportParams(extData, result)
		case 0x0057: // quic_transport_parameters (QUIC v2, RFC 9369)
			parseQUICTransportParams(extData, result)
		}

		offset += extLen
	}
}

// parseSNIExtension parses the SNI extension.
func parseSNIExtension(data []byte) string {
	if len(data) < 5 {
		return ""
	}
	// Skip list length (2 bytes) and name type (1 byte)
	nameLen := int(binary.BigEndian.Uint16(data[3:5]))
	if 5+nameLen > len(data) {
		return ""
	}
	return string(data[5 : 5+nameLen])
}

// parseALPNExtension parses the ALPN extension.
func parseALPNExtension(data []byte) []string {
	if len(data) < 2 {
		return nil
	}
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	if 2+listLen > len(data) {
		return nil
	}

	var alpns []string
	offset := 2
	for offset < 2+listLen {
		if offset >= len(data) {
			break
		}
		protoLen := int(data[offset])
		offset++
		if offset+protoLen > len(data) {
			break
		}
		alpns = append(alpns, string(data[offset:offset+protoLen]))
		offset += protoLen
	}
	return alpns
}

// parseSupportedGroups parses the supported_groups extension.
func parseSupportedGroups(data []byte) []uint16 {
	if len(data) < 2 {
		return nil
	}
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	if 2+listLen > len(data) {
		return nil
	}
	numGroups := listLen / 2
	groups := make([]uint16, numGroups)
	for i := 0; i < numGroups; i++ {
		groups[i] = binary.BigEndian.Uint16(data[2+i*2 : 4+i*2])
	}
	return groups
}

// parseSignatureAlgs parses the signature_algorithms extension.
func parseSignatureAlgs(data []byte) []uint16 {
	if len(data) < 2 {
		return nil
	}
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	if 2+listLen > len(data) {
		return nil
	}
	numAlgs := listLen / 2
	algs := make([]uint16, numAlgs)
	for i := 0; i < numAlgs; i++ {
		algs[i] = binary.BigEndian.Uint16(data[2+i*2 : 4+i*2])
	}
	return algs
}

// parseSupportedVersions parses the supported_versions extension.
func parseSupportedVersions(data []byte) []uint16 {
	if len(data) < 1 {
		return nil
	}
	listLen := int(data[0])
	if 1+listLen > len(data) {
		return nil
	}
	numVersions := listLen / 2
	versions := make([]uint16, numVersions)
	for i := 0; i < numVersions; i++ {
		versions[i] = binary.BigEndian.Uint16(data[1+i*2 : 3+i*2])
	}
	return versions
}

// parseQUICTransportParams parses QUIC transport parameters extension.
func parseQUICTransportParams(data []byte, result *IETFQUICClientHello) {
	offset := 0
	for offset < len(data) {
		if offset+4 > len(data) {
			break
		}

		// Parameter ID (variable-length integer)
		paramID, bytesRead := parseQUICVarint(data[offset:])
		if bytesRead == 0 {
			break
		}
		offset += bytesRead

		// Parameter length (variable-length integer)
		paramLen, bytesRead := parseQUICVarint(data[offset:])
		if bytesRead == 0 {
			break
		}
		offset += bytesRead

		if offset+int(paramLen) > len(data) {
			break
		}

		paramData := data[offset : offset+int(paramLen)]
		offset += int(paramLen)

		// RFC 9000 Section 18.2 - Transport Parameter Definitions
		switch paramID {
		case 0x01: // max_idle_timeout (milliseconds)
			result.MaxIdleTimeout, _ = parseQUICVarint(paramData)
		case 0x03: // max_udp_payload_size
			result.MaxUDPPayloadSize, _ = parseQUICVarint(paramData)
		case 0x04: // initial_max_data
			result.InitialMaxData, _ = parseQUICVarint(paramData)
		case 0x05: // initial_max_stream_data_bidi_local
			result.InitialMaxStreamDataBidiLocal, _ = parseQUICVarint(paramData)
		case 0x06: // initial_max_stream_data_bidi_remote
			result.InitialMaxStreamDataBidiRemote, _ = parseQUICVarint(paramData)
		case 0x07: // initial_max_stream_data_uni
			result.InitialMaxStreamDataUni, _ = parseQUICVarint(paramData)
		case 0x08: // initial_max_streams_bidi
			result.InitialMaxStreamsBidi, _ = parseQUICVarint(paramData)
		case 0x09: // initial_max_streams_uni
			result.InitialMaxStreamsUni, _ = parseQUICVarint(paramData)
		case 0x0a: // ack_delay_exponent (default: 3)
			result.AckDelayExponent, _ = parseQUICVarint(paramData)
		case 0x0b: // max_ack_delay (milliseconds, default: 25)
			result.MaxAckDelay, _ = parseQUICVarint(paramData)
		case 0x0c: // disable_active_migration (zero-length value)
			result.DisableActiveMigration = true
		case 0x0e: // active_connection_id_limit (default: 2)
			result.ActiveConnectionIDLimit, _ = parseQUICVarint(paramData)
		case 0x0f: // initial_source_connection_id
			result.InitialSourceConnectionID = make([]byte, len(paramData))
			copy(result.InitialSourceConnectionID, paramData)
		}
	}
}

// parseQUICVarint parses a QUIC variable-length integer.
// Returns the value and the number of bytes consumed.
func parseQUICVarint(data []byte) (uint64, int) {
	if len(data) == 0 {
		return 0, 0
	}

	prefix := data[0] >> 6
	switch prefix {
	case 0:
		return uint64(data[0] & 0x3f), 1
	case 1:
		if len(data) < 2 {
			return 0, 0
		}
		return uint64(binary.BigEndian.Uint16(data[:2]) & 0x3fff), 2
	case 2:
		if len(data) < 4 {
			return 0, 0
		}
		return uint64(binary.BigEndian.Uint32(data[:4]) & 0x3fffffff), 4
	case 3:
		if len(data) < 8 {
			return 0, 0
		}
		return binary.BigEndian.Uint64(data[:8]) & 0x3fffffffffffffff, 8
	}
	return 0, 0
}

// hkdfExtract performs HKDF-Extract with SHA-256.
func hkdfExtract(salt, ikm []byte) []byte {
	return hkdf.Extract(sha256.New, ikm, salt)
}

// hkdfExpandLabel performs HKDF-Expand-Label as defined in RFC 8446.
func hkdfExpandLabel(secret, label, context []byte, length int) []byte {
	// Build HKDF label
	hkdfLabel := make([]byte, 2+1+len("tls13 ")+len(label)+1+len(context))
	hkdfLabel[0] = byte(length >> 8)
	hkdfLabel[1] = byte(length)
	hkdfLabel[2] = byte(len("tls13 ") + len(label))
	copy(hkdfLabel[3:], "tls13 ")
	copy(hkdfLabel[3+len("tls13 "):], label)
	hkdfLabel[3+len("tls13 ")+len(label)] = byte(len(context))
	copy(hkdfLabel[4+len("tls13 ")+len(label):], context)

	reader := hkdf.Expand(sha256.New, secret, hkdfLabel)
	result := make([]byte, length)
	io.ReadFull(reader, result)
	return result
}

// IsIETFQUICPacket checks if the payload looks like an IETF QUIC packet.
// Note: RFC 9287 allows "greasing" the fixed bit (setting it to 0 randomly),
// so short header detection may have false negatives for greased packets.
// For comprehensive detection, connection tracking context would be needed.
func IsIETFQUICPacket(payload []byte) bool {
	if len(payload) < 5 {
		return false
	}

	// Check for long header (Form bit = 1)
	if payload[0]&0x80 != 0x80 {
		// Could be short header - check fixed bit
		// Note: RFC 9287 QUIC bit greasing may set this to 0 in valid packets.
		// Without connection tracking, we can't reliably identify greased short headers.
		// We assume fixed bit = 1 for detection, accepting false negatives for greased packets.
		return payload[0]&0x40 == 0x40
	}

	// Long header - check version
	version := binary.BigEndian.Uint32(payload[1:5])
	
	switch version {
	case quicVersionIETF1, quicVersionIETF2:
		return true
	case 0: // Version negotiation
		return true
	}

	// Check for draft versions
	return version >= 0xff000000 && version <= 0xff00001d
}

