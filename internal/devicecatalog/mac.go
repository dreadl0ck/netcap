package devicecatalog

import (
	"encoding/hex"
	"errors"
	"strings"
)

type MAC struct {
	Format  string     `json:"format"`
	Schema  int        `json:"schema"`
	Version string     `json:"version"`
	License string     `json:"license"`
	Entries []MACEntry `json:"entries"`
	index   map[string]string
}
type MACEntry struct {
	Prefix       string `json:"prefix"`
	Bits         int    `json:"bits"`
	Organization string `json:"organization"`
}

func ParseMAC(b []byte) (*MAC, error) {
	var c MAC
	if err := decode(b, &c); err != nil {
		return nil, err
	}
	if c.Format != "netcap-mac-catalogue" || c.Schema != 1 || c.Version == "" || len(c.Version) > 128 || c.License != "IEEE-secondary-nonassertion" || len(c.Entries) == 0 || len(c.Entries) > 200000 {
		return nil, errors.New("invalid MAC catalogue header")
	}
	c.index = make(map[string]string, len(c.Entries))
	for _, e := range c.Entries {
		if (e.Bits != 24 && e.Bits != 28 && e.Bits != 36) || len(e.Prefix) != e.Bits/4 || strings.Trim(e.Prefix, "0123456789ABCDEF") != "" || strings.TrimSpace(e.Organization) == "" || len(e.Organization) > 1024 || c.index[e.Prefix] != "" {
			return nil, errors.New("invalid or duplicate MAC prefix")
		}
		c.index[e.Prefix] = e.Organization
	}
	return &c, nil
}

// NormalizeMAC accepts complete 48-bit colon, hyphen or compact notation.
// Local/randomized and group addresses do not identify registered organizations.
func NormalizeMAC(mac string) string {
	if len(mac) == 17 {
		sep := mac[2]
		if sep != ':' && sep != '-' {
			return ""
		}
		for _, i := range []int{5, 8, 11, 14} {
			if mac[i] != sep {
				return ""
			}
		}
		mac = strings.ReplaceAll(mac, string(sep), "")
	}
	if len(mac) != 12 {
		return ""
	}
	b, err := hex.DecodeString(mac)
	if err != nil || b[0]&3 != 0 || mac == "000000000000" {
		return ""
	}
	return strings.ToUpper(mac)
}

func (c *MAC) Lookup(mac string) string {
	key := NormalizeMAC(mac)
	if c == nil || key == "" {
		return ""
	}
	for _, n := range []int{9, 7, 6} {
		if org := c.index[key[:n]]; org != "" {
			return org
		}
	}
	return ""
}
