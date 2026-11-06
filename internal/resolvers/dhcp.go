package resolvers

import "errors"

var ErrDHCPEnrichmentDisabled = errors.New("DHCP fingerprint enrichment disabled: no independently sourced catalogue; packet decoding remains available")

type dhcpResult struct {
	DeviceName string `json:"device_name"`
	Score      int    `json:"score"`
	Version    string `json:"version"`
}

// Compatibility entry points intentionally perform no file or network I/O.
func SaveFingerprintDB()                       {}
func InitDHCPFingerprintAPIKey()               {}
func InitDHCPFingerprintDB()                   {}
func LookupDHCPFingerprintLocal(string) string { return "" }
func LookupDHCPFingerprint(string, string, []string) (*dhcpResult, error) {
	return nil, ErrDHCPEnrichmentDisabled
}
