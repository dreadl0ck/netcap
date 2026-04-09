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
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang"
	"github.com/sirupsen/logrus"
	"go.uber.org/zap"
)

const maxGeoCacheSize = 100000

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
// This function is called when the GeolocationDB flag is enabled, so it will
// fail fatally if the databases cannot be found or loaded.
func initGeolocationDB() {
	cityPath := filepath.Join(DataBaseFolderPath, "GeoLite2-City.mmdb")
	asnPath := filepath.Join(DataBaseFolderPath, "GeoLite2-ASN.mmdb")

	resolverLog.Info("initializing geolocation databases",
		zap.String("cityDB", cityPath),
		zap.String("asnDB", asnPath),
	)

	// Check if City database file exists
	if _, err := os.Stat(cityPath); os.IsNotExist(err) {
		log.Fatalf("geolocation database not found: %s\nPlease download the GeoLite2 databases or disable geolocation with -geoDB=false", cityPath)
	}

	// Check if ASN database file exists
	if _, err := os.Stat(asnPath); os.IsNotExist(err) {
		log.Fatalf("geolocation database not found: %s\nPlease download the GeoLite2 databases or disable geolocation with -geoDB=false", asnPath)
	}

	// Initialize City reader
	if err := initCityReader(); err != nil {
		log.Fatalf("failed to open city geolocation database at %s: %v\nPlease ensure the database file is valid or disable geolocation with -geoDB=false", cityPath, err)
	}
	resolverLog.Info("successfully loaded city geolocation database",
		zap.String("path", cityPath),
	)

	// Initialize ASN reader
	if err := initAsnReader(); err != nil {
		log.Fatalf("failed to open ASN geolocation database at %s: %v\nPlease ensure the database file is valid or disable geolocation with -geoDB=false", asnPath, err)
	}
	resolverLog.Info("successfully loaded ASN geolocation database",
		zap.String("path", asnPath),
	)

	resolverLog.Info("geolocation databases initialized successfully")
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
		geoloc += fmt.Sprintf(" (%s)", city)
	}
	if record.ASN.Number > 0 {
		asn = fmt.Sprintf("ASN %d (%s)", record.ASN.Number, record.ASN.Organization)
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
