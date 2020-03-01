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

// GeoRecord is a simple Geolocation Record for fast lookups
type GeoRecord struct {
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

func initCityReader() (err error) {
	cityReader, err = maxminddb.Open(filepath.Join(dataBaseSource, "GeoLite2-City.mmdb"))

	return
}
func initAsnReader() (err error) {
	asnReader, err = maxminddb.Open(filepath.Join(dataBaseSource, "GeoLite2-ASN.mmdb"))
	return
}

func (record GeoRecord) repr() (geoloc, asn string) {
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
// results are being cached in an atomic map to avoid unnecessary lookups
func LookupGeolocation(addr string) (string, string) {
	if len(addr) == 0 {
		return "", ""
	}

	ip := net.ParseIP(addr)
	if ip == nil {
		logger.WithField("addr", addr).Error("invalid IP")
		return "", ""
	}

	if result, ok := geolocations.Load(ip.String()); ok {
		return result.(GeoRecord).repr()
	}

	if cityReader == nil {
		if err := initCityReader(); err != nil {
			logger.WithError(err).Error("failed to open city GeoDB")
		}
	}

	if asnReader == nil {
		if err := initAsnReader(); err != nil {
			logger.WithError(err).Error("failed to open ASN GeoDB")
		}
	}

	var record = GeoRecord{}
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
