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

package resolvers

import (
	"strings"
	"time"

	"github.com/gopacket/gopacket/macs"
	"go.uber.org/zap"
)

// hexVal returns the numeric value of a hex character, or 0xFF if invalid.
func hexVal(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default:
		return 0xFF
	}
}

// initMACResolver reports the built-in source; external supplements are disabled.
func initMACResolver() {
	resolverLog.Info("using gopacket's built-in MAC prefix database",
		zap.Int("prefixes", len(macs.ValidMACPrefixMap)),
	)
}

// LookupManufacturer resolves a MAC addr to the manufacturer.
// Uses only gopacket's built-in prefix data.
func LookupManufacturer(mac string) string {
	startTime := time.Now()
	cacheHit := false
	defer func() {
		if perfTracker != nil {
			perfTracker.RecordResolver("MAC", time.Since(startTime), cacheHit)
		}
	}()

	if len(mac) < 8 {
		return ""
	}

	oui := strings.ToUpper(mac[:8])

	// Fall back to gopacket's built-in MAC prefix database
	// The gopacket map uses [3]byte as key (first 3 bytes of MAC)
	// Parse the MAC address to get the first 3 bytes
	if len(mac) >= 8 {
		// Parse "E8:9F:80" or "e8:9f:80" format to [3]byte using direct hex decoding
		var prefix [3]byte
		valid := true
		for i, start := 0, 0; i < 3 && start+1 < len(oui); i++ {
			hi := hexVal(oui[start])
			lo := hexVal(oui[start+1])
			if hi == 0xFF || lo == 0xFF {
				valid = false
				break
			}
			prefix[i] = hi<<4 | lo
			start += 3 // skip "XX:"
		}
		if valid {
			if vendor, ok := macs.ValidMACPrefixMap[prefix]; ok {
				return vendor
			}
		}
	}

	return ""
}
