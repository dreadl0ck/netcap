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
	"sync/atomic"
	"time"

	"github.com/dreadl0ck/netcap/internal/devicecatalog"
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

// initMACResolver loads only an explicit reviewed supplement.
func initMACResolver() {
	initDeviceCatalogues(true, false)
	resolverLog.Info("gopacket MAC fallback available",
		zap.Int("prefixes", len(macs.ValidMACPrefixMap)),
	)
}

// LookupManufacturer returns a registered organization, not a device identity.
func LookupManufacturer(mac string) string {
	startTime := time.Now()
	cacheHit := false
	defer func() {
		if perfTracker != nil {
			perfTracker.RecordResolver("MAC", time.Since(startTime), cacheHit)
		}
	}()

	key := devicecatalog.NormalizeMAC(mac)
	if key == "" {
		return ""
	}

	if org := macCatalogue.Load().Lookup(mac); org != "" {
		return org
	}
	oui := key[:6]

	var prefix [3]byte
	for i := range prefix {
		prefix[i] = hexVal(oui[i*2])<<4 | hexVal(oui[i*2+1])
	}
	return macs.ValidMACPrefixMap[prefix]
}

var macCatalogue atomic.Pointer[devicecatalog.MAC]

func LoadMACCatalogue(path string) error {
	b, err := devicecatalog.Read(path)
	if err != nil {
		return err
	}
	c, err := devicecatalog.ParseMAC(b)
	if err != nil {
		return err
	}
	macCatalogue.Store(c)
	return nil
}
