/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

// Benchmarks for MatchesPattern. The pattern set mirrors what the
// shipped rules/examples and configs/firewall-rules use against the
// most common HTTP fields, so the numbers are representative of the
// rule engine hot path.
//
// In stub builds the HS pre-check is a no-op, so these benchmarks
// measure the pure RE2 baseline. With -tags hyperscan the same
// benchmarks measure the HS-pre-check + RE2 confirm path.

package filter

import (
	"testing"
)

var benchPatterns = []string{
	`(?i)/login`,
	`(?i)/auth`,
	`(?i)/signin`,
	`(?i)(union.*select|select.*from|insert.*into|drop.*table|delete.*from|update.*set)`,
	`(?i)(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|%252e%252e)`,
	`(?i)(sqlmap|nikto|dirbuster|gobuster|nmap|masscan|wpscan|nessus|acunetix)`,
	`(?i)wpad\.dat|proxy\.pac`,
	`(?i)(<script|javascript:|onerror=|onload=)`,
	`(?i)malware-domain\.`,
	`(?i)c2-server\.`,
	`(?i)botnet-controller\.`,
}

// Half match, half miss to mimic real traffic where most patterns don't fire.
var benchInputs = []string{
	"GET /admin/login HTTP/1.1",
	"GET /api/v1/users HTTP/1.1",
	"POST /auth/token HTTP/1.1",
	"GET /static/main.css HTTP/1.1",
	"User-Agent: Mozilla/5.0 (X11; Linux x86_64)",
	"User-Agent: nikto",
	"GET /index.html HTTP/1.1",
	"' OR '1'='1",
	"GET /wpad.dat HTTP/1.0",
	"normal benign traffic with no markers",
	"GET /api/products?id=42 HTTP/1.1",
}

func BenchmarkMatchesPattern_AllPatternsAllInputs(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		input := benchInputs[i%len(benchInputs)]
		for _, p := range benchPatterns {
			_ = MatchesPattern(input, p)
		}
	}
}

// BenchmarkMatchesPattern_MissOnly fans out the same input against
// every pattern, where none of the patterns match. This is the case
// HS dominates: a no-match early-exit avoids running RE2 entirely.
func BenchmarkMatchesPattern_MissOnly(b *testing.B) {
	b.ReportAllocs()
	miss := "totally normal request body with nothing suspicious in it"
	for i := 0; i < b.N; i++ {
		for _, p := range benchPatterns {
			if MatchesPattern(miss, p) {
				b.Fatal("expected no match")
			}
		}
	}
}

// BenchmarkMatchesPattern_HitOnly fans out an input that matches every
// pattern. This isolates the HS-then-RE2 double-scan overhead.
func BenchmarkMatchesPattern_HitOnly(b *testing.B) {
	b.ReportAllocs()
	hits := "/login /auth /signin sqlmap union.*select ../wpad.dat malware-domain.example c2-server.example botnet-controller.example <script onerror= onload=  drop_table_users  ../../etc/passwd"
	for i := 0; i < b.N; i++ {
		for _, p := range benchPatterns {
			_ = MatchesPattern(hits, p)
		}
	}
}
