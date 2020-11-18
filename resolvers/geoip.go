/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017-2020 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package resolvers

import (
	"fmt"
	"net"
	"path/filepath"
	"sync"

	"github.com/oschwald/maxminddb-golang"
	"github.com/sirupsen/logrus"
)

var (
	geolocations sync.Map
	cityReader   *maxminddb.Reader
	asnReader    *maxminddb.Reader
	logger       = logrus.New()
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
func initGeolocationDB() {
	if err := initCityReader(); err != nil {
		logger.WithError(err).Error("failed to open city GeoDB")
	}

	if err := initAsnReader(); err != nil {
		logger.WithError(err).Error("failed to open ASN GeoDB")
	}
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

	if result, ok := geolocations.Load(ip.String()); ok {
		return result.(geoRecord).repr()
	}

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

	geolocations.Store(addr, record)

	return record.repr()
}
