/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package mcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// CVELookup encapsulates the NVD JSON 2.0 API lookup plus an in-process
// LRU-ish cache so repeated lookups for the same CVE during one session
// don't hammer NVD.
//
// NVD's public CVE 2.0 API:
//
//	https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-YYYY-NNNN
//
// The endpoint is anonymous (rate-limited to 5 req / 30 s). For higher
// throughput an API key would be set via NVD_API_KEY but we don't
// require one in v1.
type CVELookup struct {
	hc      *http.Client
	enabled bool

	mu    sync.Mutex
	cache map[string]cveCacheEntry
}

type cveCacheEntry struct {
	at  time.Time
	val map[string]any
	err string // captured error (when retry would be pointless within TTL)
}

// cveIDPattern matches a CVE id of the form CVE-YYYY-NNNN+.
var cveIDPattern = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)

// NewCVELookup constructs a lookup helper. When enabled=false (or
// NETCAP_MCP_DISABLE_NETWORK=1), all calls return a clear "disabled"
// error instead of making outbound HTTP requests; useful for air-gapped
// service-mode deployments.
func NewCVELookup(enabled bool) *CVELookup {
	return &CVELookup{
		hc:      &http.Client{Timeout: 15 * time.Second},
		enabled: enabled,
		cache:   make(map[string]cveCacheEntry),
	}
}

// Lookup retrieves and normalises one CVE record. The returned map is
// safe to ship straight to an LLM (id, description, references, CVSS,
// CWEs, published/lastModified). Errors are returned for transport
// failure or rate-limiting; an unknown CVE id produces a successful
// result with `found: false`.
func (c *CVELookup) Lookup(cveID string) (map[string]any, error) {
	cveID = strings.ToUpper(strings.TrimSpace(cveID))
	if !cveIDPattern.MatchString(cveID) {
		return nil, fmt.Errorf("invalid CVE id %q (expected CVE-YYYY-NNNN+)", cveID)
	}
	if !c.enabled {
		return nil, errors.New("CVE network lookups disabled (set NETCAP_MCP_DISABLE_NETWORK=0 or pass --allow-fetch)")
	}

	// 6h positive cache, 5 min negative cache.
	c.mu.Lock()
	if e, ok := c.cache[cveID]; ok {
		if e.err != "" && time.Since(e.at) < 5*time.Minute {
			c.mu.Unlock()
			return nil, errors.New(e.err)
		}
		if e.err == "" && time.Since(e.at) < 6*time.Hour {
			out := cloneMap(e.val)
			c.mu.Unlock()
			return out, nil
		}
	}
	c.mu.Unlock()

	val, err := c.fetch(cveID)
	c.mu.Lock()
	if err != nil {
		c.cache[cveID] = cveCacheEntry{at: time.Now(), err: err.Error()}
	} else {
		c.cache[cveID] = cveCacheEntry{at: time.Now(), val: cloneMap(val)}
	}
	c.mu.Unlock()
	return val, err
}

func (c *CVELookup) fetch(cveID string) (map[string]any, error) {
	url := "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + cveID
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "netcap-mcp/1.0 (+https://github.com/dreadl0ck/netcap)")

	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("NVD: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("NVD rate-limited (%s); retry in 30s or set NVD_API_KEY", resp.Status)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("NVD %s: %s", resp.Status, truncate(string(body), 200))
	}

	var raw struct {
		TotalResults    int `json:"totalResults"`
		Vulnerabilities []struct {
			CVE struct {
				ID           string `json:"id"`
				Published    string `json:"published"`
				LastModified string `json:"lastModified"`
				Descriptions []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"descriptions"`
				Metrics struct {
					CvssMetricV31 []struct {
						CvssData struct {
							BaseScore           float64 `json:"baseScore"`
							BaseSeverity        string  `json:"baseSeverity"`
							VectorString        string  `json:"vectorString"`
							AttackVector        string  `json:"attackVector"`
							AttackComplexity    string  `json:"attackComplexity"`
							PrivilegesRequired  string  `json:"privilegesRequired"`
							UserInteraction     string  `json:"userInteraction"`
							ConfidentialityImpact string `json:"confidentialityImpact"`
							IntegrityImpact      string  `json:"integrityImpact"`
							AvailabilityImpact   string  `json:"availabilityImpact"`
						} `json:"cvssData"`
					} `json:"cvssMetricV31"`
				} `json:"metrics"`
				Weaknesses []struct {
					Description []struct {
						Lang  string `json:"lang"`
						Value string `json:"value"`
					} `json:"description"`
				} `json:"weaknesses"`
				References []struct {
					URL    string   `json:"url"`
					Source string   `json:"source"`
					Tags   []string `json:"tags"`
				} `json:"references"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("NVD decode: %w", err)
	}

	if raw.TotalResults == 0 || len(raw.Vulnerabilities) == 0 {
		return map[string]any{
			"cve_id": cveID,
			"found":  false,
			"nvd":    "https://nvd.nist.gov/vuln/detail/" + cveID,
		}, nil
	}

	v := raw.Vulnerabilities[0].CVE
	desc := ""
	for _, d := range v.Descriptions {
		if d.Lang == "en" {
			desc = d.Value
			break
		}
	}

	out := map[string]any{
		"cve_id":         v.ID,
		"found":          true,
		"published":      v.Published,
		"last_modified":  v.LastModified,
		"description":    desc,
		"nvd":            "https://nvd.nist.gov/vuln/detail/" + v.ID,
		"mitre":          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=" + v.ID,
	}

	if len(v.Metrics.CvssMetricV31) > 0 {
		m := v.Metrics.CvssMetricV31[0].CvssData
		out["cvss_v3"] = map[string]any{
			"base_score":             m.BaseScore,
			"severity":               m.BaseSeverity,
			"vector":                 m.VectorString,
			"attack_vector":          m.AttackVector,
			"attack_complexity":      m.AttackComplexity,
			"privileges_required":    m.PrivilegesRequired,
			"user_interaction":       m.UserInteraction,
			"confidentiality_impact": m.ConfidentialityImpact,
			"integrity_impact":       m.IntegrityImpact,
			"availability_impact":    m.AvailabilityImpact,
		}
	}

	cwes := []string{}
	for _, w := range v.Weaknesses {
		for _, d := range w.Description {
			if d.Lang == "en" && strings.HasPrefix(d.Value, "CWE-") {
				cwes = append(cwes, d.Value)
			}
		}
	}
	if len(cwes) > 0 {
		out["cwes"] = cwes
	}

	if len(v.References) > 0 {
		refs := make([]map[string]any, 0, len(v.References))
		for _, r := range v.References {
			refs = append(refs, map[string]any{
				"url":    r.URL,
				"source": r.Source,
				"tags":   r.Tags,
			})
			if len(refs) >= 10 {
				break
			}
		}
		out["references"] = refs
	}

	return out, nil
}

func cloneMap(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
