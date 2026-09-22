/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package discovery

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// DNS record types
const (
	dnsTypeA    = 1
	dnsTypeAAAA = 28
	dnsTypePTR  = 12
	dnsTypeSRV  = 33
)

type mdnsRecord struct {
	Name    string
	Type    uint16
	IP      string
	SRVPort uint16
	SRVHost string
}

// mdnsExtract extracts hostname and service information from mDNS traffic.
func mdnsExtract(data []byte, ident string, ts time.Time) *DiscoveryResult {
	if len(data) < 12 {
		return nil
	}

	flags := binary.BigEndian.Uint16(data[2:4])
	opcode := (flags >> 11) & 0xf
	if opcode != 0 {
		return nil
	}

	questionCount := binary.BigEndian.Uint16(data[4:6])
	answerCount := binary.BigEndian.Uint16(data[6:8])
	authorityCount := binary.BigEndian.Uint16(data[8:10])
	additionalCount := binary.BigEndian.Uint16(data[10:12])

	pos := 12

	// Skip questions
	for i := uint16(0); i < questionCount && pos < len(data); i++ {
		_, newPos := parseDNSName(data, pos)
		if newPos < 0 {
			return nil
		}
		pos = newPos + 4
	}

	var hostnames []string

	totalRRs := answerCount + authorityCount + additionalCount
	for i := uint16(0); i < totalRRs && pos < len(data)-10; i++ {
		name, newPos := parseDNSName(data, pos)
		if newPos < 0 {
			break
		}

		if newPos+10 > len(data) {
			break
		}

		rrType := binary.BigEndian.Uint16(data[newPos : newPos+2])
		rdLength := int(binary.BigEndian.Uint16(data[newPos+8 : newPos+10]))
		rdataStart := newPos + 10

		if rdataStart+rdLength > len(data) {
			break
		}

		rdata := data[rdataStart : rdataStart+rdLength]
		pos = rdataStart + rdLength

		switch rrType {
		case dnsTypeA:
			if len(rdata) >= 4 && name != "" {
				if !containsStr(hostnames, name) {
					hostnames = append(hostnames, name)
				}
			}
		case dnsTypeAAAA:
			if len(rdata) >= 16 && name != "" {
				if !containsStr(hostnames, name) {
					hostnames = append(hostnames, name)
				}
			}
		case dnsTypePTR:
			if name != "" && !containsStr(hostnames, name) {
				hostnames = append(hostnames, name)
			}
		case dnsTypeSRV:
			if len(rdata) >= 6 {
				target, _ := parseDNSName(data, rdataStart+6)
				if target != "" && !containsStr(hostnames, target) {
					hostnames = append(hostnames, target)
				}
			}
		}
	}

	if len(hostnames) == 0 {
		return nil
	}

	return &DiscoveryResult{
		Hostnames: hostnames,
	}
}

// parseDNSName parses a DNS-encoded name with compression pointer support.
func parseDNSName(data []byte, offset int) (string, int) {
	if offset >= len(data) {
		return "", -1
	}

	var parts []string
	originalOffset := offset
	jumped := false
	jumpCount := 0

	for offset < len(data) && jumpCount < 10 {
		length := int(data[offset])

		if length >= 0xC0 {
			if offset+1 >= len(data) {
				return "", -1
			}
			pointer := int(binary.BigEndian.Uint16(data[offset:offset+2]) & 0x3FFF)
			if !jumped {
				originalOffset = offset + 2
			}
			offset = pointer
			jumped = true
			jumpCount++
			continue
		}

		if length == 0 {
			if !jumped {
				originalOffset = offset + 1
			}
			break
		}

		offset++
		if offset+length > len(data) {
			return "", -1
		}
		parts = append(parts, string(data[offset:offset+length]))
		offset += length
	}

	return strings.Join(parts, "."), originalOffset
}

// formatIPv6 formats a 16-byte IPv6 address.
func formatIPv6(data []byte) string {
	if len(data) != 16 {
		return ""
	}
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

func containsStr(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
