package resolvers

import (
	"errors"
	"sync/atomic"

	"github.com/dreadl0ck/netcap/internal/devicecatalog"
)

var ErrDHCPEnrichmentDisabled = errors.New("DHCP fingerprint enrichment disabled: no admitted reviewed offline catalogue; packet decoding remains available")
var dhcpCatalogue atomic.Pointer[devicecatalog.DHCP]

// LoadDHCPCatalogue accepts a local trusted override or installer-verified path.
// Failed refreshes retain the previous immutable catalogue.
func LoadDHCPCatalogue(path string) error {
	b, err := devicecatalog.Read(path)
	if err != nil {
		return err
	}
	c, err := devicecatalog.ParseDHCP(b)
	if err != nil {
		return err
	}
	dhcpCatalogue.Store(c)
	return nil
}

type dhcpResult struct {
	DeviceName string `json:"device_name"`
	Score      int    `json:"score"`
	Version    string `json:"version"`
}

// Retired API/cache entry points perform no file or network I/O.
func SaveFingerprintDB()         {}
func InitDHCPFingerprintAPIKey() {}
func InitDHCPFingerprintDB() {
	initDeviceCatalogues(false, true)
}
func LookupDHCPFingerprintLocal(key string) string { return dhcpCatalogue.Load().Lookup(key) }
func LookupDHCPFingerprint(key string, _ string, _ []string) (*dhcpResult, error) {
	c := dhcpCatalogue.Load()
	if c == nil {
		return nil, ErrDHCPEnrichmentDisabled
	}
	label := c.Lookup(key)
	if label == "" {
		return nil, nil
	}
	return &dhcpResult{DeviceName: label}, nil
}
