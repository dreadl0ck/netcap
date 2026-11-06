package vulndb

import (
	"encoding/json"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// Reference is NVD link metadata, never downloaded content.
type Reference struct {
	URL    string   `json:"url"`
	Source string   `json:"source"`
	Tags   []string `json:"tags"`
}

// NormalizeReferences retains absolute HTTP(S) links with a host and no
// credentials, whitespace, controls or malformed escapes. Attribution is opaque.
func NormalizeReferences(refs []Reference) []Reference {
	type key struct{ url, source string }
	merged := map[key]map[string]bool{}
	for _, ref := range refs {
		if strings.IndexFunc(ref.URL, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) }) >= 0 || strings.Contains(ref.URL, `\`) {
			continue
		}
		u, err := url.Parse(ref.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.Opaque != "" {
			continue
		}
		if _, err := url.QueryUnescape(u.RawQuery); err != nil {
			continue
		}
		if port := u.Port(); port != "" {
			if _, err := strconv.ParseUint(port, 10, 16); err != nil {
				continue
			}
		}
		k := key{ref.URL, ref.Source}
		if merged[k] == nil {
			merged[k] = map[string]bool{}
		}
		for _, tag := range ref.Tags {
			merged[k][tag] = true
		}
	}
	out := make([]Reference, 0, len(merged))
	for k, tags := range merged {
		ref := Reference{URL: k.url, Source: k.source, Tags: []string{}}
		for tag := range tags {
			ref.Tags = append(ref.Tags, tag)
		}
		sort.Strings(ref.Tags)
		out = append(out, ref)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].URL == out[j].URL {
			return out[i].Source < out[j].Source
		}
		return out[i].URL < out[j].URL
	})
	return out
}

// References returns links for a CVE, or [] for a schema-1 database without
// the optional capability/table. Unknown capability versions are not interpreted.
func (d *DB) References(id string) ([]Reference, error) {
	out := []Reference{}
	if !d.references {
		return out, nil
	}
	rows, err := d.db.Query(`SELECT url,source,tags FROM nvd_references WHERE nvd_id=? ORDER BY url,source`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var ref Reference
		var tags string
		if err := rows.Scan(&ref.URL, &ref.Source, &tags); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(tags), &ref.Tags); err != nil {
			return nil, err
		}
		out = append(out, ref)
	}
	return NormalizeReferences(out), rows.Err()
}
