/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package mcp

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// log4shellCanned is a trimmed NVD 2.0 response for CVE-2021-44228, kept
// inline so tests can drive a fake NVD without external network access.
const log4shellCanned = `{
 "totalResults": 1,
 "vulnerabilities": [{
  "cve": {
   "id": "CVE-2021-44228",
   "published": "2021-12-10T10:15:09.143",
   "lastModified": "2024-11-21T06:30:34.187",
   "descriptions": [
    {"lang":"en","value":"Apache Log4j2 2.0-beta9 through 2.15.0 ... remote code execution ..."},
    {"lang":"es","value":"Apache Log4j2 2.0-beta9 a 2.15.0 ... ejecucion remota de codigo ..."}
   ],
   "metrics": {
    "cvssMetricV31": [{
     "cvssData": {
      "baseScore": 10.0,
      "baseSeverity": "CRITICAL",
      "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
      "attackVector": "NETWORK",
      "attackComplexity": "LOW",
      "privilegesRequired": "NONE",
      "userInteraction": "NONE",
      "confidentialityImpact": "HIGH",
      "integrityImpact": "HIGH",
      "availabilityImpact": "HIGH"
     }
    }]
   },
   "weaknesses": [
    {"description":[{"lang":"en","value":"CWE-502"}]},
    {"description":[{"lang":"en","value":"CWE-20"}]}
   ],
   "references": [
    {"url":"https://logging.apache.org/log4j/2.x/security.html","source":"security@apache.org","tags":["Vendor Advisory"]}
   ]
  }
 }]
}`

// TestCVELookupFetchesAndNormalises drives a fake NVD endpoint and
// asserts the normalisation produces the shape the LLM expects.
func TestCVELookupFetchesAndNormalises(t *testing.T) {
	var hits int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, log4shellCanned)
	}))
	defer ts.Close()

	c := NewCVELookup(true)
	c.hc = ts.Client()
	// Override the NVD URL by replacing the host in-flight via a custom
	// RoundTripper that redirects all NVD requests to ts.
	c.hc.Transport = redirectingTransport{to: ts.URL, inner: http.DefaultTransport}

	out, err := c.Lookup("CVE-2021-44228")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if out["found"] != true {
		t.Errorf("found = %v", out["found"])
	}
	if out["cve_id"] != "CVE-2021-44228" {
		t.Errorf("cve_id = %v", out["cve_id"])
	}
	desc, _ := out["description"].(string)
	if !strings.Contains(desc, "remote code execution") {
		t.Errorf("description: %q", desc)
	}
	cvss, _ := out["cvss_v3"].(map[string]any)
	if cvss == nil || cvss["base_score"].(float64) != 10.0 {
		t.Errorf("cvss = %v", out["cvss_v3"])
	}
	cwes, _ := out["cwes"].([]string)
	if len(cwes) != 2 || cwes[0] != "CWE-502" {
		t.Errorf("cwes = %v", out["cwes"])
	}
	refs, _ := out["references"].([]map[string]any)
	if len(refs) != 1 || refs[0]["url"] != "https://logging.apache.org/log4j/2.x/security.html" {
		t.Errorf("references = %v", out["references"])
	}

	// Cache hit: a second call must not increment hits.
	if _, err := c.Lookup("CVE-2021-44228"); err != nil {
		t.Fatalf("cached Lookup: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("expected 1 NVD hit (cached on 2nd call), got %d", got)
	}
}

// TestCVELookupInvalidID rejects bogus ids before any HTTP call.
func TestCVELookupInvalidID(t *testing.T) {
	c := NewCVELookup(true)
	for _, bad := range []string{"", "CVE-2021", "FOO-2021-1234", "CVE-21-44228", "CVE-2021-12"} {
		if _, err := c.Lookup(bad); err == nil {
			t.Errorf("Lookup(%q) = nil err, want error", bad)
		}
	}
}

// TestCVELookupDisabledReturnsError makes sure air-gapped deployments
// don't accidentally hit NVD.
func TestCVELookupDisabledReturnsError(t *testing.T) {
	c := NewCVELookup(false)
	_, err := c.Lookup("CVE-2021-44228")
	if err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Errorf("got err=%v, want disabled message", err)
	}
}

// TestCVELookupUnknownReturnsFoundFalse: NVD 0-result case maps to a
// successful response with found=false plus the canonical NVD link.
func TestCVELookupUnknownReturnsFoundFalse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"totalResults":0,"vulnerabilities":[]}`)
	}))
	defer ts.Close()

	c := NewCVELookup(true)
	c.hc.Transport = redirectingTransport{to: ts.URL, inner: http.DefaultTransport}

	out, err := c.Lookup("CVE-2099-99999")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if out["found"] != false {
		t.Errorf("found = %v", out["found"])
	}
}

// TestCVELookupRateLimited surfaces 429 with an actionable message.
func TestCVELookupRateLimited(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "go slow", http.StatusTooManyRequests)
	}))
	defer ts.Close()

	c := NewCVELookup(true)
	c.hc.Transport = redirectingTransport{to: ts.URL, inner: http.DefaultTransport}

	_, err := c.Lookup("CVE-2021-44228")
	if err == nil || !strings.Contains(err.Error(), "rate-limited") {
		t.Errorf("err = %v, want rate-limited", err)
	}
	// Negative cache: a follow-up shouldn't hit again until TTL.
	if _, err := c.Lookup("CVE-2021-44228"); err == nil {
		t.Errorf("expected cached negative error")
	}
}

// redirectingTransport rewrites the outbound URL to point at the test
// server while preserving the path and query. This is the minimum
// machinery to test the NVD integration without monkeypatching.
type redirectingTransport struct {
	to    string
	inner http.RoundTripper
}

func (r redirectingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req2 := req.Clone(req.Context())
	override, _ := http.NewRequest(req.Method, r.to+req.URL.RequestURI(), req.Body)
	req2.URL = override.URL
	req2.Host = override.Host
	return r.inner.RoundTrip(req2)
}

// guard against test flake from time-dependent caching.
var _ = time.Now
