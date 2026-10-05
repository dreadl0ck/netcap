/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
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
	"go.uber.org/zap"
)

const maxGeoCacheSize = 100000

var ErrGeolocationDBMissing = errors.New("geolocation database not found")

var (
	geolocations   = make(map[string]geoRecord)
	geolocationsMu sync.RWMutex
	geoMu          sync.RWMutex
	geoProviders   []geoProvider
)

type geoProvider struct {
	name      string
	city, asn *maxminddb.Reader
}

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

func closeGeoProviders() {
	for _, p := range geoProviders {
		p.city.Close()
		p.asn.Close()
	}
	geoProviders = nil
	geolocationsMu.Lock()
	geolocations = make(map[string]geoRecord)
	geolocationsMu.Unlock()
}

func initGeolocationDB() error {
	geoMu.Lock()
	defer geoMu.Unlock()
	closeGeoProviders()
	order, err := GeoProviderOrder(CurrentConfig.GeoProviders)
	if err != nil {
		return err
	}
	var corrupt error
	for _, name := range order {
		files := GeoFiles(name)
		cityPath, asnPath := filepath.Join(DataBaseFolderPath, files.City), filepath.Join(DataBaseFolderPath, files.ASN)
		if _, err := os.Stat(cityPath); err != nil {
			resolverLog.Warn("skipping geolocation provider", zap.String("provider", name), zap.Error(err))
			continue
		}
		if _, err := os.Stat(asnPath); err != nil {
			resolverLog.Warn("skipping geolocation provider", zap.String("provider", name), zap.Error(err))
			continue
		}
		city, err := OpenGeoDatabase(cityPath, name, "City")
		if err != nil {
			corrupt = err
			resolverLog.Warn("skipping geolocation provider", zap.String("provider", name), zap.Error(err))
			continue
		}
		asn, err := OpenGeoDatabase(asnPath, name, "ASN")
		if err != nil {
			city.Close()
			corrupt = err
			resolverLog.Warn("skipping geolocation provider", zap.String("provider", name), zap.Error(err))
			continue
		}
		geoProviders = append(geoProviders, geoProvider{name, city, asn})
		resolverLog.Info("loaded geolocation provider", zap.String("provider", name), zap.Uint("cityBuild", city.Metadata.BuildEpoch), zap.Uint("asnBuild", asn.Metadata.BuildEpoch))
	}
	if len(geoProviders) == 0 {
		if corrupt != nil {
			return corrupt
		}
		return fmt.Errorf("%w: selected providers %v in %s", ErrGeolocationDBMissing, order, DataBaseFolderPath)
	}
	return nil
}

func (record geoRecord) repr() (geoloc, asn string) {
	geoloc = record.Country.ISOCode
	if city := record.City.Names["en"]; city != "" {
		geoloc += " (" + city + ")"
	}
	if record.ASN.Number > 0 {
		asn = "ASN " + strconv.FormatInt(record.ASN.Number, 10) + " (" + record.ASN.Organization + ")"
	}
	return
}

// DB-IP's broad IPv6 location fallback is not evidence of an allocated address.
func usableDBIPLocation(ip net.IP, asn int64) bool {
	return ip.IsGlobalUnicast() && (ip.To4() != nil || (ip[0]&0xe0 == 0x20 && asn > 0))
}

func LookupGeolocation(addr string) (string, string) {
	startTime := time.Now()
	cacheHit := false
	defer func() {
		if perfTracker != nil {
			perfTracker.RecordResolver("Geolocation", time.Since(startTime), cacheHit)
		}
	}()
	ip := net.ParseIP(addr)
	if ip == nil {
		return "", ""
	}
	geoMu.RLock()
	defer geoMu.RUnlock()
	if len(geoProviders) == 0 {
		return "", ""
	}
	key := ip.String()
	geolocationsMu.RLock()
	record, found := geolocations[key]
	geolocationsMu.RUnlock()
	if found {
		cacheHit = true
		return record.repr()
	}
	for _, provider := range geoProviders {
		var candidate geoRecord
		if err := provider.asn.Lookup(ip, &candidate.ASN); err != nil {
			resolverLog.Warn("ASN lookup failed", zap.String("provider", provider.name), zap.Error(err))
		}
		if record.ASN.Number == 0 && candidate.ASN.Number > 0 {
			record.ASN = candidate.ASN
		}
		if record.Country.ISOCode == "" && (provider.name != "dbip" || usableDBIPLocation(ip, candidate.ASN.Number)) {
			if err := provider.city.Lookup(ip, &candidate); err != nil {
				resolverLog.Warn("city lookup failed", zap.String("provider", provider.name), zap.Error(err))
			}
			if candidate.Country.ISOCode != "" {
				record.Country, record.City = candidate.Country, candidate.City
			}
		}
		if record.Country.ISOCode != "" && record.ASN.Number > 0 {
			break
		}
	}
	geolocationsMu.Lock()
	if len(geolocations) >= maxGeoCacheSize {
		geolocations = make(map[string]geoRecord, maxGeoCacheSize/2)
	}
	geolocations[key] = record
	geolocationsMu.Unlock()
	return record.repr()
}

type GeoContext struct {
	Country   string
	ASN       string
	Providers []string
}

func LookupGeoContext(addr string) GeoContext {
	ip := net.ParseIP(addr)
	if ip == nil || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
		return GeoContext{}
	}
	_, _ = LookupGeolocation(addr)
	geoMu.RLock()
	defer geoMu.RUnlock()
	geolocationsMu.RLock()
	record := geolocations[ip.String()]
	geolocationsMu.RUnlock()
	context := GeoContext{Country: record.Country.ISOCode}
	if record.ASN.Number > 0 {
		context.ASN = strconv.FormatInt(record.ASN.Number, 10)
	}
	for _, provider := range geoProviders {
		context.Providers = append(context.Providers, provider.name)
	}
	return context
}
