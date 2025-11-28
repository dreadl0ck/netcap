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

package credentials

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/dreadl0ck/netcap/types"
)

const serviceNBNS = "NBNS"

// NBNS constants
const (
	nbnsPort            = 137
	nbnsMinResponseSize = 73
	nbnsNameOffset      = 57
	nbnsNameLength      = 15
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
func nbnsHarvesterFunc(data []byte, ident string, ts time.Time) *types.Credentials {
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

	// We're primarily interested in responses (node status responses)
	// But queries can also reveal information
	_ = isResponse

	// Skip header and parse names
	pos := 12

	// Try to extract NBNS name from response
	records := extractNBNSRecords(data, pos)
	if len(records) == 0 {
		// Try legacy extraction for simple responses
		record := extractLegacyNBNSName(data)
		if record != nil {
			records = append(records, record)
		}
	}

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

	notes := "NetBIOS Name Service"
	if opcode == 0 {
		notes += " - Name Query"
	} else if opcode == 5 {
		notes += " - Registration"
	}
	if len(details) > 0 {
		notes += " | " + strings.Join(details, ", ")
	}

	return &types.Credentials{
		Timestamp: ts.UnixNano(),
		Service:   serviceNBNS,
		Flow:      ident,
		User:      strings.Join(hostnames, ", "),
		Password:  "",
		Notes:     notes,
	}
}

// extractNBNSRecords parses NBNS response to extract all name records
func extractNBNSRecords(data []byte, startPos int) []*nbnsRecord {
	var records []*nbnsRecord
	pos := startPos

	// Skip the question section if present
	// Question format: Name(variable) + Type(2) + Class(2)

	// Look for node status response which contains multiple names
	// The node status response has a name list after the header

	// Find the resource record section
	for pos < len(data)-20 {
		// Check if this looks like a NetBIOS encoded name
		if data[pos] == 0x20 { // Length byte for encoded name (32 bytes)
			name, newPos := decodeNBNSName(data, pos)
			if name != "" && newPos > pos {
				record := &nbnsRecord{
					Name: name,
				}

				// Try to extract suffix type (16th character of original name)
				if newPos+10 < len(data) {
					// Skip to resource data
					rdLength := int(binary.BigEndian.Uint16(data[newPos+8 : newPos+10]))
					rdataPos := newPos + 10

					if rdataPos+rdLength <= len(data) && rdLength >= 4 {
						// IP address in resource data
						record.IPAddress = fmt.Sprintf("%d.%d.%d.%d",
							data[rdataPos], data[rdataPos+1],
							data[rdataPos+2], data[rdataPos+3])
					}
				}

				records = append(records, record)
				pos = newPos
				continue
			}
		}
		pos++
	}

	return records
}

// decodeNBNSName decodes a NetBIOS encoded name
// NetBIOS names are encoded by splitting each byte into two half-bytes,
// adding 'A' to each, resulting in a 32-character uppercase string
func decodeNBNSName(data []byte, offset int) (string, int) {
	if offset >= len(data) {
		return "", offset
	}

	length := int(data[offset])
	if length != 32 { // NetBIOS encoded names are always 32 bytes
		return "", offset
	}
	offset++

	if offset+32 > len(data) {
		return "", offset
	}

	var decoded []byte
	for i := 0; i < 32; i += 2 {
		high := data[offset+i] - 'A'
		low := data[offset+i+1] - 'A'
		char := (high << 4) | low
		decoded = append(decoded, char)
	}
	offset += 32

	// Skip null terminator if present
	if offset < len(data) && data[offset] == 0 {
		offset++
	}

	// Extract suffix type (last byte before padding)
	var suffix byte
	name := strings.TrimRight(string(decoded[:15]), " ")
	if len(decoded) >= 16 {
		suffix = decoded[15]
	}

	// Look up suffix description
	suffixDesc := ""
	if desc, ok := nbnsSuffixTypes[suffix]; ok {
		suffixDesc = desc
	}

	// Validate the decoded name contains printable characters
	if !isValidNBNSName(name) {
		return "", offset
	}

	// Append suffix description to name for context
	if suffixDesc != "" {
		return name, offset
	}

	return name, offset
}

// extractLegacyNBNSName extracts hostname from simple NBNS response format
func extractLegacyNBNSName(data []byte) *nbnsRecord {
	if len(data) < nbnsMinResponseSize {
		return nil
	}

	// Simple extraction from fixed offset (works for many responses)
	nameBytes := data[nbnsNameOffset : nbnsNameOffset+nbnsNameLength]
	name := strings.TrimRight(string(nameBytes), " \x00")

	// Validate the name
	if !isValidNBNSName(name) {
		return nil
	}

	return &nbnsRecord{
		Name: name,
	}
}

// isValidNBNSName checks if the extracted name looks valid
func isValidNBNSName(name string) bool {
	if len(name) == 0 || len(name) > 15 {
		return false
	}

	// First character should be printable
	if len(name) > 0 && !unicode.IsPrint(rune(name[0])) {
		return false
	}

	// Should contain mostly alphanumeric characters
	validChars := 0
	for _, c := range name {
		if unicode.IsLetter(c) || unicode.IsDigit(c) || c == '-' || c == '_' {
			validChars++
		}
	}

	// At least 50% should be valid characters
	return float64(validChars)/float64(len(name)) > 0.5
}

// containsNBNSString checks if a string slice contains a specific string
func containsNBNSString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
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
