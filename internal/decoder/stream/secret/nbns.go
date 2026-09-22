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

package secret

import (
	"encoding/binary"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/dreadl0ck/netcap/types"
)

const serviceNBNS = "NBNS"

// NBNS constants
const (
	nbnsPort            = 137
	nbnsMinResponseSize = 56 // Minimum size for a valid NBNS response with one name
	nbnsHeaderSize      = 12
)

// NBNS opcode values
const (
	nbnsOpcodeQuery        = 0
	nbnsOpcodeRegistration = 5
	nbnsOpcodeRelease      = 6
	nbnsOpcodeWACK         = 7
	nbnsOpcodeRefresh      = 8
)

// NBNS suffix types (16th byte of NetBIOS name)
var nbnsSuffixTypes = map[byte]string{
	0x00: "Workstation",
	0x03: "Messenger",
	0x06: "RAS Server",
	0x1B: "Domain Master Browser",
	0x1C: "Domain Controller",
	0x1D: "Master Browser",
	0x1E: "Browser Election",
	0x1F: "NetDDE",
	0x20: "File Server",
	0x21: "RAS Client",
	0x22: "MS Exchange Interchange",
	0x23: "MS Exchange Store",
	0x24: "MS Exchange Directory",
	0x30: "Modem Sharing Server",
	0x31: "Modem Sharing Client",
	0x43: "SMS Clients Remote Control",
	0x44: "SMS Admin Remote Control Tool",
	0x45: "SMS Clients Remote Chat",
	0x46: "SMS Clients Remote Transfer",
	0x4C: "DEC Pathworks TCPIP",
	0x52: "DEC Pathworks TCPIP",
	0x87: "MS Exchange MTA",
	0x6A: "MS Exchange IMC",
	0xBE: "Network Monitor Agent",
	0xBF: "Network Monitor Application",
}

// nbnsRecord represents a parsed NBNS record
type nbnsRecord struct {
	Name       string
	SuffixType byte
	SuffixDesc string
	Group      bool
	IPAddress  string
}

// nbnsHarvesterFunc extracts hostname information from NBNS (NetBIOS Name Service) traffic.
// NBNS is used for Windows network name resolution and can reveal computer names and domains.
// Note: Port filtering is now handled centrally by the harvester engine (HarvesterPortFilter setting)
func nbnsHarvesterFunc(data []byte, ident string, ts time.Time) *types.Secret {
	if len(data) < nbnsMinResponseSize {
		return nil
	}

	// Parse NBNS header
	// [0-1]: Transaction ID
	// [2-3]: Flags
	// [4-5]: Questions
	// [6-7]: Answer RRs
	// [8-9]: Authority RRs
	// [10-11]: Additional RRs

	flags := binary.BigEndian.Uint16(data[2:4])
	isResponse := (flags >> 15) & 0x1
	opcode := (flags >> 11) & 0xf
	rcode := flags & 0xf // Response code

	// Only process valid opcodes
	if opcode > nbnsOpcodeRefresh {
		return nil
	}

	// Check for error responses (rcode != 0 means error)
	if isResponse == 1 && rcode != 0 {
		return nil
	}

	// Get question and answer counts
	qdCount := binary.BigEndian.Uint16(data[4:6])
	anCount := binary.BigEndian.Uint16(data[6:8])

	// Sanity check: reasonable counts
	if qdCount > 10 || anCount > 50 {
		return nil
	}

	// Skip header and parse names
	pos := nbnsHeaderSize

	// Try to extract NBNS name from response
	records := extractNBNSRecords(data, pos, anCount)
	if len(records) == 0 {
		return nil
	}

	// Format extracted information
	var hostnames []string
	var details []string

	for _, record := range records {
		if record.Name != "" && !containsNBNSString(hostnames, record.Name) {
			hostnames = append(hostnames, record.Name)
		}

		detail := record.Name
		if record.SuffixDesc != "" {
			detail = fmt.Sprintf("%s <%s>", record.Name, record.SuffixDesc)
		}
		if record.IPAddress != "" {
			detail += fmt.Sprintf(" [%s]", record.IPAddress)
		}
		if record.Group {
			detail += " (Group)"
		}
		details = append(details, detail)
	}

	if len(hostnames) == 0 {
		return nil
	}

	notes := "NetBIOS Name Service"
	switch opcode {
	case nbnsOpcodeQuery:
		notes += " | Query"
	case nbnsOpcodeRegistration:
		notes += " | Registration"
	case nbnsOpcodeRelease:
		notes += " | Release"
	case nbnsOpcodeRefresh:
		notes += " | Refresh"
	}
	if len(details) > 0 {
		notes += " | " + strings.Join(details, ", ")
	}

	return &types.Secret{
		Timestamp: ts.UnixNano(),
		Service:   serviceNBNS,
		Flow:      ident,
		User:      strings.Join(hostnames, ", "),
		Password:  "",
		Notes:     notes,
	}
}

// extractNBNSRecords parses NBNS response to extract all name records
func extractNBNSRecords(data []byte, startPos int, anCount uint16) []*nbnsRecord {
	var records []*nbnsRecord
	pos := startPos

	// Limit iterations to prevent infinite loops on malformed data
	maxIterations := 20
	iterations := 0

	// Find and decode NetBIOS encoded names
	for pos < len(data)-34 && iterations < maxIterations {
		iterations++

		// Check if this looks like a NetBIOS encoded name
		// Length byte should be 0x20 (32 bytes for encoded name)
		if data[pos] == 0x20 {
			// Validate the encoded data before attempting decode
			if !isValidEncodedNBNSData(data, pos+1, 32) {
				pos++
				continue
			}

			name, suffixType, suffixDesc, newPos := decodeNBNSName(data, pos)
			if name != "" && newPos > pos {
				record := &nbnsRecord{
					Name:       name,
					SuffixType: suffixType,
					SuffixDesc: suffixDesc,
				}

				// Try to extract IP address from resource data
				// Resource record format after name: Type(2) + Class(2) + TTL(4) + RDLength(2) + RData
				if newPos+10 < len(data) {
					rdLength := int(binary.BigEndian.Uint16(data[newPos+8 : newPos+10]))
					rdataPos := newPos + 10

					if rdataPos+rdLength <= len(data) && rdLength >= 4 {
						ip := fmt.Sprintf("%d.%d.%d.%d",
							data[rdataPos], data[rdataPos+1],
							data[rdataPos+2], data[rdataPos+3])
						// Validate IP address looks reasonable
						if isValidIPAddress(data[rdataPos : rdataPos+4]) {
							record.IPAddress = ip
						}
					}
				}

				// Only add if we haven't already seen this name
				if !containsNBNSRecord(records, record.Name) {
					records = append(records, record)
				}

				pos = newPos
				continue
			}
		}
		pos++
	}

	return records
}

// isValidEncodedNBNSData checks if the bytes at the given offset are valid NetBIOS encoded data
// NetBIOS encoding uses bytes in range 'A' (0x41) to 'P' (0x50)
func isValidEncodedNBNSData(data []byte, offset, length int) bool {
	if offset+length > len(data) {
		return false
	}

	for i := range length {
		b := data[offset+i]
		if b < 'A' || b > 'P' {
			return false
		}
	}
	return true
}

// isValidIPAddress performs basic validation on an IP address
func isValidIPAddress(ip []byte) bool {
	if len(ip) != 4 {
		return false
	}

	// Reject obviously invalid IPs
	// All zeros
	if ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] == 0 {
		return false
	}
	// Broadcast
	if ip[0] == 255 && ip[1] == 255 && ip[2] == 255 && ip[3] == 255 {
		return false
	}

	return true
}

// containsNBNSRecord checks if a record slice contains a record with the given name
func containsNBNSRecord(records []*nbnsRecord, name string) bool {
	for _, r := range records {
		if r.Name == name {
			return true
		}
	}
	return false
}

// decodeNBNSName decodes a NetBIOS encoded name
// NetBIOS names are encoded by splitting each byte into two half-bytes,
// adding 'A' to each, resulting in a 32-character uppercase string
// Returns: name, suffixType, suffixDesc, newOffset
func decodeNBNSName(data []byte, offset int) (string, byte, string, int) {
	if offset >= len(data) {
		return "", 0, "", offset
	}

	length := int(data[offset])
	if length != 32 { // NetBIOS encoded names are always 32 bytes
		return "", 0, "", offset
	}
	offset++

	if offset+32 > len(data) {
		return "", 0, "", offset
	}

	var decoded []byte
	for i := 0; i < 32; i += 2 {
		high := data[offset+i] - 'A'
		low := data[offset+i+1] - 'A'
		// Sanity check: nibbles should be 0-15
		if high > 15 || low > 15 {
			return "", 0, "", offset + 32
		}
		char := (high << 4) | low
		decoded = append(decoded, char)
	}
	offset += 32

	// Skip null terminator if present
	if offset < len(data) && data[offset] == 0 {
		offset++
	}

	if len(decoded) < 16 {
		return "", 0, "", offset
	}

	// Extract suffix type (16th byte, which is the type indicator)
	suffix := decoded[15]

	// Extract name (first 15 bytes, trimmed of padding spaces)
	name := strings.TrimRight(string(decoded[:15]), " \x00")

	// Look up suffix description
	suffixDesc := ""
	if desc, ok := nbnsSuffixTypes[suffix]; ok {
		suffixDesc = desc
	}

	// Validate the decoded name
	if !isValidNBNSName(name) {
		return "", 0, "", offset
	}

	return name, suffix, suffixDesc, offset
}

// isValidNBNSName checks if the extracted name looks like a valid NetBIOS name
func isValidNBNSName(name string) bool {
	if len(name) == 0 || len(name) > 15 {
		return false
	}

	// Minimum length for a meaningful name
	if len(name) < 2 {
		return false
	}

	// First character must be alphanumeric (NetBIOS naming convention)
	firstRune := rune(name[0])
	if !unicode.IsLetter(firstRune) && !unicode.IsDigit(firstRune) {
		return false
	}

	// Count valid and invalid characters
	alphanumCount := 0
	invalidCount := 0
	nonASCIICount := 0

	for _, c := range name {
		// Check for non-ASCII characters (control chars, extended chars)
		if c > 127 || c < 32 {
			nonASCIICount++
			continue
		}

		switch {
		case unicode.IsLetter(c):
			alphanumCount++
		case unicode.IsDigit(c):
			alphanumCount++
		case c == '-' || c == '_':
			// These are allowed in NetBIOS names
		case c == ' ':
			// Trailing spaces are allowed (padding), but we've already trimmed them
			// Interior spaces are unusual but can occur
		case !unicode.IsPrint(c):
			// Non-printable characters are invalid
			return false
		case c == '"' || c == '\'' || c == '`' || c == '|' || c == '<' || c == '>' ||
			c == '[' || c == ']' || c == '{' || c == '}' || c == '(' || c == ')' ||
			c == '=' || c == '+' || c == '*' || c == '&' || c == '%' || c == '$' ||
			c == '#' || c == '@' || c == '!' || c == '~' || c == '^' || c == '\\' ||
			c == '/' || c == ':' || c == ';' || c == '?' || c == ',':
			// Special characters that shouldn't appear in NetBIOS names
			invalidCount++
		default:
			// Other characters - count as potentially invalid
			if !unicode.IsPrint(c) {
				return false
			}
		}
	}

	// Reject names with non-ASCII characters (like □ symbols from binary data)
	if nonASCIICount > 0 {
		return false
	}

	// Reject names with invalid characters
	if invalidCount > 0 {
		return false
	}

	// At least 70% should be alphanumeric characters
	if float64(alphanumCount)/float64(len(name)) < 0.7 {
		return false
	}

	// Reject names that look like garbage/random bytes
	// NetBIOS names are typically words or abbreviations, not random character sequences
	if looksLikeGarbage(name) {
		return false
	}

	return true
}

// looksLikeGarbage detects names that appear to be misinterpreted binary data
func looksLikeGarbage(name string) bool {
	if len(name) == 0 {
		return true
	}

	// Check for repeating characters (e.g., "UUUUUUUUUUUUUUU")
	if hasRepeatingChars(name, 4) {
		return true
	}

	// Check for hex-like strings (e.g., "E04784589605A88")
	if looksLikeHex(name) {
		return true
	}

	// Check for excessive digit sequences (e.g., "030sM4003004004")
	consecutiveDigits := 0
	maxConsecutiveDigits := 0
	digitCount := 0
	upperCount := 0
	lowerCount := 0

	for _, c := range name {
		if unicode.IsDigit(c) {
			consecutiveDigits++
			digitCount++
			if consecutiveDigits > maxConsecutiveDigits {
				maxConsecutiveDigits = consecutiveDigits
			}
		} else {
			consecutiveDigits = 0
		}
		if unicode.IsUpper(c) {
			upperCount++
		}
		if unicode.IsLower(c) {
			lowerCount++
		}
	}

	// If more than 50% are digits and there are long digit sequences, likely garbage
	if len(name) > 4 && float64(digitCount)/float64(len(name)) > 0.5 && maxConsecutiveDigits >= 3 {
		return true
	}

	// Check for unusual character patterns that indicate garbage
	// e.g., lowercase followed by uppercase mixed randomly
	transitions := 0
	lastUpper := false
	lastLower := false
	for _, c := range name {
		isUpper := unicode.IsUpper(c)
		isLower := unicode.IsLower(c)

		if isUpper && lastLower {
			transitions++
		} else if isLower && lastUpper {
			transitions++
		}

		lastUpper = isUpper
		lastLower = isLower
	}

	// Many case transitions in a short name is suspicious
	// (Real names like "WORKSTATION1" don't have many transitions)
	if len(name) > 3 && transitions > len(name)/2 {
		return true
	}

	// All lowercase with digits mixed in and no clear word structure is suspicious
	// e.g., "zcxczc1c1c2ewc3" - random lowercase with interspersed digits
	if len(name) > 6 && upperCount == 0 && lowerCount > 0 && digitCount > 0 {
		// Check if it looks like random chars rather than a word
		if !looksLikeWord(name) {
			return true
		}
	}

	return false
}

// hasRepeatingChars checks if the name has a character repeated consecutively
func hasRepeatingChars(name string, minRepeat int) bool {
	if len(name) < minRepeat {
		return false
	}

	count := 1
	var lastChar rune
	for i, c := range name {
		if i == 0 {
			lastChar = c
			continue
		}
		if c == lastChar {
			count++
			if count >= minRepeat {
				return true
			}
		} else {
			count = 1
			lastChar = c
		}
	}
	return false
}

// looksLikeHex checks if the name appears to be a hex string
func looksLikeHex(name string) bool {
	if len(name) < 8 {
		return false
	}

	hexChars := 0
	for _, c := range name {
		// Hex characters: 0-9, A-F, a-f
		if (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f') {
			hexChars++
		}
	}

	// If more than 90% are valid hex characters and length is typical for hex strings
	if float64(hexChars)/float64(len(name)) > 0.9 {
		// Additional check: real NetBIOS names don't typically have this pattern
		// Check if it has the pattern of uppercase hex (like "E04784589605A88")
		upperHex := 0
		for _, c := range name {
			if (c >= 'A' && c <= 'F') || (c >= '0' && c <= '9') {
				upperHex++
			}
		}
		if float64(upperHex)/float64(len(name)) > 0.9 {
			return true
		}
	}
	return false
}

// looksLikeWord checks if a lowercase string looks like it could be a real word/name
func looksLikeWord(name string) bool {
	// Count consonant and vowel clusters
	vowels := "aeiou"
	consecutiveConsonants := 0
	maxConsecutiveConsonants := 0

	for _, c := range strings.ToLower(name) {
		if !unicode.IsLetter(c) {
			consecutiveConsonants = 0
			continue
		}
		if strings.ContainsRune(vowels, c) {
			consecutiveConsonants = 0
		} else {
			consecutiveConsonants++
			if consecutiveConsonants > maxConsecutiveConsonants {
				maxConsecutiveConsonants = consecutiveConsonants
			}
		}
	}

	// More than 4 consecutive consonants is unusual in English/common words
	// e.g., "zcxczc" has many consecutive consonants
	if maxConsecutiveConsonants > 4 {
		return false
	}

	// Check for repetitive patterns like "c1c1c2"
	if hasRepetitivePattern(name) {
		return false
	}

	return true
}

// hasRepetitivePattern checks for suspicious repetitive patterns
func hasRepetitivePattern(name string) bool {
	// Check for 2-char patterns repeated (like "c1c1" or "zc zc")
	if len(name) < 4 {
		return false
	}

	for i := 0; i < len(name)-3; i++ {
		pattern := name[i : i+2]
		rest := name[i+2:]
		if strings.Contains(rest, pattern) {
			// Found a repeated 2-char pattern
			return true
		}
	}

	return false
}

// containsNBNSString checks if a string slice contains a specific string
func containsNBNSString(slice []string, s string) bool {
	return slices.Contains(slice, s)
}

// nbnsHarvester is the harvester definition for NBNS
var nbnsHarvester = Harvester{
	Name:          "NBNS",
	Description:   "NetBIOS Name Service - captures Windows network hostname discovery",
	HarvesterFunc: nbnsHarvesterFunc,
}

// NBNS request packet for active discovery (reference only)
var nbnsRequestPacket = []byte{
	0x82, 0x28, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x20, 0x43, 0x4B, 0x41, 0x41, 0x41, 0x41, 0x41,
	0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
	0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
	0x41, 0x41, 0x41, 0x41, 0x41, 0x00, 0x00, 0x21, 0x00, 0x01,
}
