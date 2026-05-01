/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

// Benchmarks for the CMS-detection HTTP-response matcher. Compares the
// pure-RE2 nested-loop baseline against the optional Hyperscan
// prefilter (when -tags hyperscan is set). The HS path is toggled at
// runtime by clearing the per-source HS index so a single binary can
// compare both modes apples-to-apples.

package software

import (
	"os"
	"path/filepath"
	"testing"

	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/types"
	"go.uber.org/zap"
)

// loadRealCMSDB points DataBaseFolderPath at a directory containing
// cmsdb.json (default: ~/.config/netcap/dbs) and re-runs loadCmsDB plus
// buildCMSHSIndex. Returns false (and the bench Skips) if the file is
// not present.
func loadRealCMSDB(tb testing.TB) bool {
	tb.Helper()

	if softwareLog == nil {
		softwareLog = zap.NewNop()
	}
	if decoderconfig.Instance == nil {
		decoderconfig.Instance = decoderconfig.DefaultConfig
	}

	candidates := []string{
		resolvers.DataBaseFolderPath,
	}
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates, filepath.Join(home, ".config", "netcap", "dbs"))
	}

	for _, dir := range candidates {
		if _, err := os.Stat(filepath.Join(dir, "cmsdb.json")); err == nil {
			resolvers.DataBaseFolderPath = dir
			cmsDB = make(map[string]*cmsInfo)
			if err := loadCmsDB(); err != nil {
				tb.Logf("loadCmsDB failed at %s: %v", dir, err)
				continue
			}
			buildCMSHSIndex()
			return true
		}
	}
	return false
}

// realisticHTTPResponses returns a representative mix of HTTP responses
// that real-world capture traffic produces: well-known servers, several
// CMS frameworks, a pure-miss case.
func realisticHTTPResponses() []*types.HTTP {
	return []*types.HTTP{
		{
			Timestamp: 1,
			ResponseHeader: map[string]string{
				"Server":       "nginx/1.18.0",
				"X-Powered-By": "PHP/7.4.3",
				"link":         `<https://example.com/wp-json/>; rel="https://api.w.org/"`,
			},
		},
		{
			Timestamp: 2,
			ResponseHeader: map[string]string{
				"Server":      "Apache/2.4.41",
				"X-Generator": "Drupal 9 (https://www.drupal.org)",
			},
		},
		{
			Timestamp: 3,
			ResponseHeader: map[string]string{
				"Server":             "Microsoft-IIS/10.0",
				"X-AspNet-Version":   "4.0.30319",
				"X-Powered-By":       "ASP.NET",
				"X-AspNetMvc-Version": "5.2",
			},
		},
		{
			Timestamp: 4,
			ResponseHeader: map[string]string{
				"Server":     "cloudflare",
				"CF-Ray":     "abc123",
				"CF-Cache-Status": "HIT",
			},
		},
		{
			Timestamp: 5,
			ResponseHeader: map[string]string{
				"Server":       "gws",
				"X-XSS-Protection": "0",
			},
		},
		// Pure miss: response headers with no CMS markers.
		{
			Timestamp: 6,
			ResponseHeader: map[string]string{
				"Content-Type":   "application/json",
				"Cache-Control":  "no-cache",
				"Content-Length": "1234",
			},
		},
	}
}

// BenchmarkCMSDetect_All runs the realistic mix with the HS prefilter
// active (when compiled with -tags hyperscan) or as a pure RE2 baseline
// (in stub builds).
func BenchmarkCMSDetect_All(b *testing.B) {
	if !loadRealCMSDB(b) {
		b.Skip("cmsdb.json not found in DataBaseFolderPath / ~/.config/netcap/dbs")
	}
	resetCMSHSIndexForBench(b, true)

	responses := realisticHTTPResponses()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = WhatSoftwareHTTP("bench", responses[i%len(responses)])
	}
}

// BenchmarkCMSDetect_NoHyperscan runs the same mix without the HS
// prefilter so the same binary can A/B compare.
func BenchmarkCMSDetect_NoHyperscan(b *testing.B) {
	if !loadRealCMSDB(b) {
		b.Skip("cmsdb.json not found in DataBaseFolderPath / ~/.config/netcap/dbs")
	}
	resetCMSHSIndexForBench(b, false)

	responses := realisticHTTPResponses()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = WhatSoftwareHTTP("bench", responses[i%len(responses)])
	}
}

// BenchmarkCMSDetect_MissOnly isolates the worst case for the baseline
// (every response forces a full cmsDB sweep).
func BenchmarkCMSDetect_MissOnly(b *testing.B) {
	if !loadRealCMSDB(b) {
		b.Skip("cmsdb.json not found")
	}
	resetCMSHSIndexForBench(b, true)

	miss := &types.HTTP{
		Timestamp: 1,
		ResponseHeader: map[string]string{
			"Content-Type":   "application/json",
			"Cache-Control":  "no-cache",
			"Content-Length": "1234",
		},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = WhatSoftwareHTTP("bench", miss)
	}
}

// BenchmarkCMSDetect_MissOnly_NoHyperscan baseline for the above.
func BenchmarkCMSDetect_MissOnly_NoHyperscan(b *testing.B) {
	if !loadRealCMSDB(b) {
		b.Skip("cmsdb.json not found")
	}
	resetCMSHSIndexForBench(b, false)

	miss := &types.HTTP{
		Timestamp: 1,
		ResponseHeader: map[string]string{
			"Content-Type":   "application/json",
			"Cache-Control":  "no-cache",
			"Content-Length": "1234",
		},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = WhatSoftwareHTTP("bench", miss)
	}
}
