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
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/types"
)

const serviceMDNS = "mDNS"

// mDNS constants
const (
	mdnsPort = 5353

	// DNS record types
	dnsTypeA    = 1
	dnsTypeAAAA = 28
	dnsTypePTR  = 12
	dnsTypeTXT  = 16
	dnsTypeSRV  = 33
)

// mDNS query/response flags
const (
	dnsQRQuery    = 0
	dnsQRResponse = 1
)

// mdnsRecord represents a parsed mDNS resource record
type mdnsRecord struct {
	Name    string
	Type    uint16
	Class   uint16
	TTL     uint32
	IP      string
	TXTData []string
	SRVData *srvRecord
}

type srvRecord struct {
	Priority uint16
	Weight   uint16
	Port     uint16
	Target   string
}

// mdnsHarvesterFunc extracts hostname information from mDNS (Multicast DNS) traffic.
// mDNS is used for local network service discovery (Bonjour, Avahi).
// This captures device names, services, and IP mappings.
func mdnsHarvesterFunc(data []byte, ident string, ts time.Time) *types.Credentials {
	if len(data) < 12 {
		return nil
	}

	// Parse DNS header
	// [0-1]: Transaction ID
	// [2-3]: Flags
	// [4-5]: Questions
	// [6-7]: Answer RRs
	// [8-9]: Authority RRs
	// [10-11]: Additional RRs

	flags := binary.BigEndian.Uint16(data[2:4])
	qr := (flags >> 15) & 0x1
	opcode := (flags >> 11) & 0xf

	// We're interested in standard queries (opcode 0)
	if opcode != 0 {
		return nil
	}

	questionCount := binary.BigEndian.Uint16(data[4:6])
	answerCount := binary.BigEndian.Uint16(data[6:8])
	authorityCount := binary.BigEndian.Uint16(data[8:10])
	additionalCount := binary.BigEndian.Uint16(data[10:12])

	pos := 12

	// Skip questions section
	for i := uint16(0); i < questionCount && pos < len(data); i++ {
		name, newPos := parseDNSName(data, pos)
		if newPos < 0 || name == "" {
			return nil
		}
		pos = newPos + 4 // Skip QTYPE and QCLASS
	}

	// Parse answer records
	var hostnames []string
	var ipMappings []string
	var services []string

	totalRRs := answerCount + authorityCount + additionalCount
	for i := uint16(0); i < totalRRs && pos < len(data)-10; i++ {
		record := parseDNSResourceRecord(data, pos)
		if record == nil {
			break
		}

		// Update position based on record parsing
		name, newPos := parseDNSName(data, pos)
		if newPos < 0 {
			break
		}
		pos = newPos + 10 // Name + TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2)

		rdLength := int(binary.BigEndian.Uint16(data[newPos+8 : newPos+10]))
		pos += rdLength

		if name == "" {
			continue
		}

		// Extract useful information based on record type
		switch record.Type {
		case dnsTypeA, dnsTypeAAAA:
			if record.IP != "" {
				ipMappings = append(ipMappings, fmt.Sprintf("%s=%s", record.Name, record.IP))
				if !containsString(hostnames, record.Name) {
					hostnames = append(hostnames, record.Name)
				}
			}
		case dnsTypePTR:
			// PTR records contain service/device names
			if !containsString(hostnames, record.Name) {
				hostnames = append(hostnames, record.Name)
			}
		case dnsTypeSRV:
			if record.SRVData != nil {
				services = append(services, fmt.Sprintf("%s:%d", record.SRVData.Target, record.SRVData.Port))
			}
		case dnsTypeTXT:
			// TXT records may contain service metadata
			for _, txt := range record.TXTData {
				if strings.Contains(txt, "=") {
					// Key-value pair in TXT record
					services = append(services, txt)
				}
			}
		}
	}

	// Only create credential if we found useful data
	if len(hostnames) == 0 && len(ipMappings) == 0 {
		return nil
	}

	// Format the discovered information
	var notes strings.Builder
	if qr == dnsQRQuery {
		notes.WriteString("mDNS Query - ")
	} else {
		notes.WriteString("mDNS Response - ")
	}

	if len(ipMappings) > 0 {
		notes.WriteString("Mappings: ")
		notes.WriteString(strings.Join(ipMappings, ", "))
	}

	if len(services) > 0 {
		if notes.Len() > 20 {
			notes.WriteString(" | ")
		}
		notes.WriteString("Services: ")
		notes.WriteString(strings.Join(services, ", "))
	}

	return &types.Credentials{
		Timestamp: ts.UnixNano(),
		Service:   serviceMDNS,
		Flow:      ident,
		User:      strings.Join(hostnames, ", "), // Store hostnames in user field
		Password:  "",
		Notes:     notes.String(),
	}
}

// parseDNSName parses a DNS-encoded name with support for compression pointers
func parseDNSName(data []byte, offset int) (string, int) {
	if offset >= len(data) {
		return "", -1
	}

	var parts []string
	originalOffset := offset
	jumped := false
	jumpCount := 0
	maxJumps := 10 // Prevent infinite loops

	for offset < len(data) && jumpCount < maxJumps {
		length := int(data[offset])

		// Check for compression pointer
		if length >= 0xC0 {
			if offset+1 >= len(data) {
				return "", -1
			}
			// Compression pointer - get new offset
			pointer := int(binary.BigEndian.Uint16(data[offset:offset+2]) & 0x3FFF)
			if !jumped {
				originalOffset = offset + 2
			}
			offset = pointer
			jumped = true
			jumpCount++
			continue
		}

		// End of name
		if length == 0 {
			if !jumped {
				originalOffset = offset + 1
			}
			break
		}

		// Regular label
		offset++
		if offset+length > len(data) {
			return "", -1
		}
		parts = append(parts, string(data[offset:offset+length]))
		offset += length
	}

	return strings.Join(parts, "."), originalOffset
}

// parseDNSResourceRecord parses a DNS resource record
func parseDNSResourceRecord(data []byte, offset int) *mdnsRecord {
	name, newOffset := parseDNSName(data, offset)
	if newOffset < 0 || newOffset+10 > len(data) {
		return nil
	}

	record := &mdnsRecord{
		Name:  name,
		Type:  binary.BigEndian.Uint16(data[newOffset : newOffset+2]),
		Class: binary.BigEndian.Uint16(data[newOffset+2 : newOffset+4]),
		TTL:   binary.BigEndian.Uint32(data[newOffset+4 : newOffset+8]),
	}

	rdLength := int(binary.BigEndian.Uint16(data[newOffset+8 : newOffset+10]))
	rdataStart := newOffset + 10

	if rdataStart+rdLength > len(data) {
		return record // Return partial record
	}

	rdata := data[rdataStart : rdataStart+rdLength]

	// Parse RDATA based on type
	switch record.Type {
	case dnsTypeA:
		if len(rdata) >= 4 {
			record.IP = fmt.Sprintf("%d.%d.%d.%d", rdata[0], rdata[1], rdata[2], rdata[3])
		}
	case dnsTypeAAAA:
		if len(rdata) >= 16 {
			record.IP = formatIPv6(rdata[:16])
		}
	case dnsTypeSRV:
		if len(rdata) >= 6 {
			record.SRVData = &srvRecord{
				Priority: binary.BigEndian.Uint16(rdata[0:2]),
				Weight:   binary.BigEndian.Uint16(rdata[2:4]),
				Port:     binary.BigEndian.Uint16(rdata[4:6]),
			}
			if len(rdata) > 6 {
				target, _ := parseDNSName(data, rdataStart+6)
				record.SRVData.Target = target
			}
		}
	case dnsTypeTXT:
		// TXT records contain one or more strings
		pos := 0
		for pos < len(rdata) {
			txtLen := int(rdata[pos])
			pos++
			if pos+txtLen <= len(rdata) {
				record.TXTData = append(record.TXTData, string(rdata[pos:pos+txtLen]))
			}
			pos += txtLen
		}
	}

	return record
}

// formatIPv6 formats a 16-byte IPv6 address
func formatIPv6(data []byte) string {
	if len(data) != 16 {
		return ""
	}

	// Check for IPv4-mapped IPv6
	if bytes.Equal(data[:10], []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}) &&
		bytes.Equal(data[10:12], []byte{0xff, 0xff}) {
		return fmt.Sprintf("::ffff:%d.%d.%d.%d", data[12], data[13], data[14], data[15])
	}

	var parts []string
	for i := 0; i < 16; i += 2 {
		parts = append(parts, fmt.Sprintf("%x", binary.BigEndian.Uint16(data[i:i+2])))
	}
	return strings.Join(parts, ":")
}

// containsString checks if a string slice contains a specific string
func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

// mdnsHarvester is the harvester definition for mDNS
var mdnsHarvester = Harvester{
	Name:          "mDNS",
	Description:   "Multicast DNS - captures local network service discovery hostnames and IP mappings",
	HarvesterFunc: mdnsHarvesterFunc,
}
