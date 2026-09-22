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
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang"
	"github.com/sirupsen/logrus"
	"go.uber.org/zap"
)

const maxGeoCacheSize = 100000

// ErrGeolocationDBMissing reports an absent GeoLite2 database. Callers match
// on it to tell "not downloaded yet", which is actionable, from "corrupt",
// which is not the same remedy.
var ErrGeolocationDBMissing = errors.New("geolocation database not found")

var (
	geolocations   = make(map[string]geoRecord)
	geolocationsMu sync.RWMutex
	cityReader     *maxminddb.Reader
	asnReader      *maxminddb.Reader
	logger         = logrus.New()
)

// geoRecord is a simple Geolocation Record for fast lookups.
type geoRecord struct {
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	ASN struct {
		Organization string `maxminddb:"autonomous_system_organization"`
		Number       int64  `maxminddb:"autonomous_system_number"`
	}
}

// initGeolocationDB opens handles to the geolocation databases.
//
// It reports a problem instead of terminating the process. This used to be
// four log.Fatalf calls, which made a missing 61 MB database indistinguishable
// from a crash: the GUI spawns this binary and saw only "exit status 1" before
// the first packet was read, on every clean install of every platform, because
// no installer ships these databases. LookupGeolocation already nil-checks
// both readers, so a failure here costs geolocation enrichment and nothing
// else.
func initGeolocationDB() error {
	cityPath := filepath.Join(DataBaseFolderPath, "GeoLite2-City.mmdb")
	asnPath := filepath.Join(DataBaseFolderPath, "GeoLite2-ASN.mmdb")

	resolverLog.Info("initializing geolocation databases",
		zap.String("cityDB", cityPath),
		zap.String("asnDB", asnPath),
	)

	// Check if City database file exists
	if _, err := os.Stat(cityPath); os.IsNotExist(err) {
		return fmt.Errorf("%w: %s", ErrGeolocationDBMissing, cityPath)
	}

	// Check if ASN database file exists
	if _, err := os.Stat(asnPath); os.IsNotExist(err) {
		return fmt.Errorf("%w: %s", ErrGeolocationDBMissing, asnPath)
	}

	// Initialize City reader
	if err := initCityReader(); err != nil {
		return fmt.Errorf("failed to open city geolocation database at %s: %w", cityPath, err)
	}
	resolverLog.Info("successfully loaded city geolocation database",
		zap.String("path", cityPath),
	)

	// Initialize ASN reader
	if err := initAsnReader(); err != nil {
		return fmt.Errorf("failed to open ASN geolocation database at %s: %w", asnPath, err)
	}
	resolverLog.Info("successfully loaded ASN geolocation database",
		zap.String("path", asnPath),
	)

	resolverLog.Info("geolocation databases initialized successfully")

	return nil
}

func initCityReader() (err error) {
	cityReader, err = maxminddb.Open(filepath.Join(DataBaseFolderPath, "GeoLite2-City.mmdb"))

	return
}

func initAsnReader() (err error) {
	asnReader, err = maxminddb.Open(filepath.Join(DataBaseFolderPath, "GeoLite2-ASN.mmdb"))

	return
}

func (record geoRecord) repr() (geoloc, asn string) {
	geoloc = record.Country.ISOCode
	if city, ok := record.City.Names["en"]; ok {
		geoloc += " (" + city + ")"
	}
	if record.ASN.Number > 0 {
		asn = "ASN " + strconv.FormatInt(record.ASN.Number, 10) + " (" + record.ASN.Organization + ")"
	}
	return
}

// LookupGeolocation returns all associated geolocations for a given address and db handle
// results are being cached in an atomic map to avoid unnecessary lookups.
func LookupGeolocation(addr string) (string, string) {
	startTime := time.Now()
	cacheHit := false
	defer func() {
		if perfTracker != nil {
			perfTracker.RecordResolver("Geolocation", time.Since(startTime), cacheHit)
		}
	}()

	if asnReader == nil || cityReader == nil {
		return "", ""
	}
	if len(addr) == 0 {
		return "", ""
	}

	ip := net.ParseIP(addr)
	if ip == nil {
		logger.WithField("addr", addr).Error("invalid IP")

		return "", ""
	}

	ipStr := ip.String()

	geolocationsMu.RLock()
	if result, ok := geolocations[ipStr]; ok {
		geolocationsMu.RUnlock()
		cacheHit = true
		return result.repr()
	}
	geolocationsMu.RUnlock()

	record := geoRecord{}
	err := cityReader.Lookup(ip, &record)
	if err != nil {
		logger.WithError(err).Error("failed to lookup city")

		return "", ""
	}

	err = asnReader.Lookup(ip, &record.ASN)
	if err != nil {
		logger.WithError(err).Error("failed to lookup asn")
	}

	geolocationsMu.Lock()
	// evict cache if it grows too large
	if len(geolocations) >= maxGeoCacheSize {
		geolocations = make(map[string]geoRecord, maxGeoCacheSize/2)
	}
	geolocations[ipStr] = record
	geolocationsMu.Unlock()

	return record.repr()
}
