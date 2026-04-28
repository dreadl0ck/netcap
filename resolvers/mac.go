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
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"log"
	"path/filepath"
	"strings"
	"time"

	"github.com/gopacket/gopacket/macs"
	"go.uber.org/zap"
)

// https://macaddress.io/database/macaddress.io-db.json
// Single record:
// {
//     "oui":"08:EC:F5",
//     "isPrivate":false,
//     "companyName":"Cisco Systems, Inc",
//     "companyAddress":"80 West Tasman Drive San Jose CA 94568",
//     "countryCode":"US",
//     "assignmentBlockSize":"MA-L",
//     "dateCreated":"2018-11-09",
//     "dateUpdated":"2018-11-09"
// }

// macSummary contains infos about a specific OUI.
type macSummary struct {
	OUI         string `json:"oui"`
	IsPrivate   bool   `json:"isPrivate"`
	CompanyName string `json:"companyName"`
	CountryCode string `json:"countryCode"`
}

var macDB = make(map[string]macSummary)

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

// initMACResolver loads the MAC DB into memory.
// It first attempts to use gopacket's built-in MAC prefix data,
// and optionally supplements it with the JSON database from macaddress.io if available.
func initMACResolver() {
	var sums int

	// First, try to load the optional JSON database as a supplement
	dbPath := filepath.Join(DataBaseFolderPath, "macaddress.io-db.json")
	data, err := os.ReadFile(dbPath)
	if err != nil {
		// Not an error - we'll use gopacket's built-in data only
		resolverLog.Info("macaddress.io-db.json not found, using gopacket's built-in MAC prefix database")
	} else {
		// Load additional entries from JSON database if available
		for line := range bytes.SplitSeq(data, []byte{'\n'}) {
			if len(line) == 0 {
				continue
			}

			var sum macSummary
			if err = json.Unmarshal(line, &sum); err != nil {
				if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
					break
				}
				log.Println("failed to unmarshal record:", err, string(line), "in macaddress.io-db.json")
				continue
			}

			macDB[strings.ToUpper(sum.OUI)] = sum
			sums++
		}
		resolverLog.Info("loaded additional OUI summaries from JSON",
			zap.Int("total", sums),
			zap.String("from", dbPath),
		)
	}

	// Log that we're also using gopacket's built-in database
	resolverLog.Info("using gopacket's built-in MAC prefix database",
		zap.Int("prefixes", len(macs.ValidMACPrefixMap)),
	)
}

// LookupManufacturer resolves a MAC addr to the manufacturer.
// It first checks the optional JSON database, then falls back to gopacket's built-in data.
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

	// First check the JSON database if it was loaded
	if res, ok := macDB[oui]; ok {
		cacheHit = true
		// Skip entries that are redacted in free version
		if !strings.Contains(res.CompanyName, "REDACTED") {
			return res.CompanyName
		}
	}

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
