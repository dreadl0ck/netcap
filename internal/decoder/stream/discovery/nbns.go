/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package discovery

import (
	"encoding/binary"
	"net"
	"strings"
	"time"
	"unicode"
)

const (
	nbnsMinResponseSize = 56
	nbnsHeaderSize      = 12
	nbnsOpcodeRefresh   = 8
)

// NBNS suffix types — maps to device roles
var nbnsSuffixRoles = map[byte]string{
	0x00: "Workstation",
	0x03: "Messenger",
	0x06: "RAS Server",
	0x1B: "Domain Master Browser",
	0x1C: "Domain Controller",
	0x1D: "Master Browser",
	0x1E: "Browser Election",
	0x20: "File Server",
	0x21: "RAS Client",
}

// nbnsExtract extracts hostname and role information from NBNS traffic.
func nbnsExtract(data []byte, ident string, ts time.Time) *DiscoveryResult {
	if len(data) < nbnsMinResponseSize {
		return nil
	}

	flags := binary.BigEndian.Uint16(data[2:4])
	isResponse := (flags >> 15) & 0x1
	opcode := (flags >> 11) & 0xf
	rcode := flags & 0xf

	if opcode > nbnsOpcodeRefresh {
		return nil
	}
	if isResponse == 1 && rcode != 0 {
		return nil
	}

	qdCount := int(binary.BigEndian.Uint16(data[4:6]))
	anCount := int(binary.BigEndian.Uint16(data[6:8]))
	if qdCount > 10 || anCount > 50 || isResponse == 0 && opcode != 5 && opcode != 8 {
		return nil
	}
	pos := nbnsHeaderSize
	var question int
	for range qdCount {
		question = pos
		_, _, end := nbnsDecodeName(data, pos)
		if end <= pos || end+4 > len(data) {
			return nil
		}
		pos = end + 4
	}
	// Registration binds its question name using the additional NB resource.
	count := anCount
	if isResponse == 0 {
		count = int(binary.BigEndian.Uint16(data[10:12]))
	}
	for range count {
		namePos := pos
		if pos+2 <= len(data) && data[pos]&0xc0 == 0xc0 {
			namePos = int(binary.BigEndian.Uint16(data[pos:pos+2]) & 0x3fff)
			pos += 2
		} else {
			_, _, end := nbnsDecodeName(data, pos)
			if end <= pos {
				return nil
			}
			pos = end
		}
		if pos+10 > len(data) {
			return nil
		}
		typ, size := binary.BigEndian.Uint16(data[pos:]), int(binary.BigEndian.Uint16(data[pos+8:]))
		pos += 10
		if pos+size > len(data) {
			return nil
		}
		if namePos == question && question == 0 {
			return nil
		}
		name, role, _ := nbnsDecodeName(data, namePos)
		if typ == 0x20 && size >= 6 && size%6 == 0 && binary.BigEndian.Uint16(data[pos:])&0x8000 == 0 && name != "" {
			ip := net.IP(data[pos+2 : pos+6])
			if !ip.IsUnspecified() && !ip.IsMulticast() {
				return &DiscoveryResult{Hostnames: []string{name}, Roles: []string{role}, SourceIP: ip.String()}
			}
		}
		pos += size
	}
	return nil
}

type nbnsRec struct {
	name string
	role string
}

func nbnsExtractRecords(data []byte, startPos int) []nbnsRec {
	var records []nbnsRec
	pos := startPos

	for i := 0; i < 20 && pos < len(data)-34; i++ {
		if data[pos] != 0x20 {
			pos++
			continue
		}

		if !nbnsIsValidEncoded(data, pos+1, 32) {
			pos++
			continue
		}

		name, role, newPos := nbnsDecodeName(data, pos)
		if name != "" && newPos > pos {
			records = append(records, nbnsRec{name: name, role: role})
			pos = newPos
		} else {
			pos++
		}
	}

	return records
}

func nbnsIsValidEncoded(data []byte, offset, length int) bool {
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

func nbnsDecodeName(data []byte, offset int) (string, string, int) {
	if offset >= len(data) || int(data[offset]) != 32 {
		return "", "", offset
	}
	offset++

	if offset+32 > len(data) {
		return "", "", offset
	}

	var decoded []byte
	for i := 0; i < 32; i += 2 {
		high := data[offset+i] - 'A'
		low := data[offset+i+1] - 'A'
		if high > 15 || low > 15 {
			return "", "", offset + 32
		}
		decoded = append(decoded, (high<<4)|low)
	}
	offset += 32

	if offset < len(data) && data[offset] == 0 {
		offset++
	}

	if len(decoded) < 16 {
		return "", "", offset
	}

	suffix := decoded[15]
	name := strings.TrimRight(string(decoded[:15]), " \x00")

	if !nbnsIsValidName(name) {
		return "", "", offset
	}

	role, _ := nbnsSuffixRoles[suffix]
	if suffix != 0x00 && suffix != 0x03 && suffix != 0x20 {
		return "", role, offset // Browser/controller registrations name domains.
	}
	return name, role, offset
}

func nbnsIsValidName(name string) bool {
	if len(name) < 2 || len(name) > 15 {
		return false
	}

	first := rune(name[0])
	if !unicode.IsLetter(first) && !unicode.IsDigit(first) {
		return false
	}

	alphaNum := 0
	for _, c := range name {
		if c > 127 || c < 32 {
			return false
		}
		if unicode.IsLetter(c) || unicode.IsDigit(c) {
			alphaNum++
		} else if !unicode.IsPrint(c) {
			return false
		}
	}

	if float64(alphaNum)/float64(len(name)) < 0.7 {
		return false
	}

	// Reject repeating characters (garbage data)
	if len(name) >= 4 {
		same := 1
		for i := 1; i < len(name); i++ {
			if name[i] == name[i-1] {
				same++
				if same >= 4 {
					return false
				}
			} else {
				same = 1
			}
		}
	}

	return true
}
