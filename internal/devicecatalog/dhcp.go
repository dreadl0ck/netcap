package devicecatalog

import (
	"errors"
	"strconv"
	"strings"
)

type Candidate struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

type DHCP struct {
	Format       string      `json:"format"`
	Schema       int         `json:"schema"`
	Version      string      `json:"version"`
	License      string      `json:"license"`
	SourceSHA256 string      `json:"source_sha256"`
	Entries      []DHCPEntry `json:"entries"`
	index        map[string][]Candidate
}
type DHCPEntry struct {
	Key        string      `json:"key"`
	Candidates []Candidate `json:"candidates"`
}

func ParseDHCP(b []byte) (*DHCP, error) {
	var c DHCP
	if err := decode(b, &c); err != nil {
		return nil, err
	}
	if c.Format != "netcap-dhcp-catalogue" || c.Schema != 1 || c.Version == "" || len(c.Version) > 128 || c.License != "ODbL-1.0 AND DbCL-1.0" || len(c.SourceSHA256) != 64 || strings.Trim(c.SourceSHA256, "0123456789abcdef") != "" || len(c.Entries) == 0 || len(c.Entries) > 100000 {
		return nil, errors.New("invalid DHCP catalogue header")
	}
	c.index = make(map[string][]Candidate, len(c.Entries))
	for _, e := range c.Entries {
		if !ValidKey(e.Key) || len(e.Candidates) == 0 || len(e.Candidates) > 32 || c.index[e.Key] != nil {
			return nil, errors.New("invalid or duplicate DHCP key")
		}
		seen := map[string]bool{}
		for _, candidate := range e.Candidates {
			if candidate.ID == "" || len(candidate.ID) > 128 || strings.TrimSpace(candidate.Label) == "" || len(candidate.Label) > 512 || seen[candidate.ID] {
				return nil, errors.New("invalid DHCP candidate")
			}
			seen[candidate.ID] = true
		}
		c.index[e.Key] = e.Candidates
	}
	return &c, nil
}

func ValidKey(key string) bool {
	if key == "" || len(key) > 1023 {
		return false
	}
	parts := strings.Split(key, ",")
	if len(parts) > 256 {
		return false
	}
	for _, p := range parts {
		n, err := strconv.ParseUint(p, 10, 8)
		if err != nil || strconv.FormatUint(n, 10) != p {
			return false
		}
	}
	return true
}

func (c *DHCP) Candidates(key string) []Candidate {
	if c == nil {
		return nil
	}
	return append([]Candidate(nil), c.index[key]...)
}

// Lookup refuses collisions rather than choosing an arbitrary historical label.
func (c *DHCP) Lookup(key string) string {
	if c == nil {
		return ""
	}
	if v := c.index[key]; len(v) == 1 {
		return v[0].Label
	}
	return ""
}

type Option struct {
	Code, Length int
	Data         []byte
}

// ParameterKey implements RFC 2132 option 55 and RFC 3396 concatenation,
// including RFC 2132 option-overloaded file then sname fields.
func ParameterKey(options []Option, file, sname []byte) string {
	var params []byte
	var overload byte
	seenOverload := false
	for _, o := range options {
		if o.Code < 0 || o.Code > 255 {
			return ""
		}
		if o.Code != 0 && o.Code != 255 && (o.Length != len(o.Data) || o.Length > 255 || o.Length < 0) {
			return ""
		}
		if o.Code == 255 {
			break
		}
		if o.Code == 55 {
			params = append(params, o.Data...)
		}
		if o.Code == 52 {
			if seenOverload || len(o.Data) != 1 || o.Data[0] < 1 || o.Data[0] > 3 {
				return ""
			}
			seenOverload, overload = true, o.Data[0]
		}
	}
	for i, field := range [][]byte{file, sname} {
		if overload&(1<<i) == 0 {
			continue
		}
		for pos := 0; pos < len(field); {
			code := field[pos]
			pos++
			if code == 255 {
				break
			}
			if code == 0 {
				continue
			}
			if pos >= len(field) {
				return ""
			}
			n := int(field[pos])
			pos++
			if n > len(field)-pos || code == 52 {
				return ""
			}
			if code == 55 {
				params = append(params, field[pos:pos+n]...)
			}
			pos += n
		}
	}
	if len(params) == 0 || len(params) > 256 {
		return ""
	}
	parts := make([]string, len(params))
	for i, b := range params {
		parts[i] = strconv.Itoa(int(b))
	}
	return strings.Join(parts, ",")
}
