/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

// Benchmarks for the nmap-style service-probe matcher. Compares the
// pure-RE2 baseline against the optional Hyperscan prefilter (when the
// `hyperscan` build tag is set). The HS path is toggled at runtime by
// swapping the per-category index in/out so a single binary can compare
// both modes apples-to-apples.

package service

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/resolvers"
	"go.uber.org/zap"
)

// Representative banners spanning protocols where nmap probes typically
// fire. Mix of immediate hits (expectedCategory) and misses (forces the
// "scan all categories" code path which is where multi-pattern HS shines).
var benchBanners = []struct {
	port   int32
	proto  string
	banner string
}{
	{21, "TCP", "220 (vsFTPd 3.0.3)\r\n"},
	{22, "TCP", "SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3\r\n"},
	{25, "TCP", "220 mail.example.com ESMTP Postfix (Ubuntu)\r\n"},
	{80, "TCP", "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0 (Ubuntu)\r\nContent-Type: text/html\r\n\r\n<html>"},
	{110, "TCP", "+OK Dovecot ready.\r\n"},
	{143, "TCP", "* OK [CAPABILITY IMAP4rev1] Dovecot ready.\r\n"},
	{443, "TCP", "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\n\r\n"},
	{3306, "TCP", "\x4e\x00\x00\x00\x0a8.0.32-0ubuntu0.20.04.2\x00"},
	{6379, "TCP", "+PONG\r\n"},
	{0, "TCP", "this banner matches no probe at all\r\n"}, // pure-miss case
	{0, "TCP", "RANDOM GIBBERISH 12345 NOT A REAL PROTOCOL\r\n"},
}

// loadRealProbes is a once-per-binary side-effect that points
// resolvers.DataBaseFolderPath at a directory containing
// nmap-service-probes (we accept the standard Homebrew location, then a
// few other common paths) and runs initServiceProbes. Returns nil if no
// probes file is reachable so benchmarks can Skip gracefully.
func loadRealProbes(tb testing.TB) bool {
	tb.Helper()

	if serviceLog == nil {
		serviceLog = zap.NewNop()
	}

	candidates := []string{
		"/opt/homebrew/share/nmap",
		"/usr/local/share/nmap",
		"/usr/share/nmap",
	}
	for _, dir := range candidates {
		if _, err := os.Stat(filepath.Join(dir, "nmap-service-probes")); err == nil {
			resolvers.DataBaseFolderPath = dir
			decoderconfig.Instance = decoderconfig.DefaultConfig
			decoderconfig.Instance.UseRE2 = true
			if err := initServiceProbes(); err != nil {
				tb.Logf("initServiceProbes failed at %s: %v", dir, err)
				continue
			}
			return true
		}
	}
	return false
}

func benchService(port int32, proto string) *service {
	s := NewService(time.Now().UnixNano(), 0, 0, "")
	s.IP = "127.0.0.1"
	s.Port = port
	s.Protocol = proto
	s.Flows = []string{"127.0.0.1:1234->127.0.0.1:" + itoa(int(port))}
	return s
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	buf := [10]byte{}
	i := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// BenchmarkServiceProbeMatch_All cycles through every banner, exercising
// both the expectedCategory hit path and the "scan all categories" miss
// path. This is the closest analogue to real-world capture traffic.
func BenchmarkServiceProbeMatch_All(b *testing.B) {
	if !loadRealProbes(b) {
		b.Skip("nmap-service-probes not found; install nmap to run this benchmark")
	}
	// Force the canonical state: full HS prefilter active when compiled
	// with -tags hyperscan, no-op stub otherwise.
	resetServiceProbeHSIndexForBench(b, true)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bb := benchBanners[i%len(benchBanners)]
		s := benchService(bb.port, bb.proto)
		MatchServiceProbes(s, []byte(bb.banner), "bench")
	}
}

// BenchmarkServiceProbeMatch_NoHyperscan disables the HS prefilter at
// runtime so the same binary can measure the pure RE2 baseline.
func BenchmarkServiceProbeMatch_NoHyperscan(b *testing.B) {
	if !loadRealProbes(b) {
		b.Skip("nmap-service-probes not found; install nmap to run this benchmark")
	}
	resetServiceProbeHSIndexForBench(b, false)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bb := benchBanners[i%len(benchBanners)]
		s := benchService(bb.port, bb.proto)
		MatchServiceProbes(s, []byte(bb.banner), "bench")
	}
}

// BenchmarkServiceProbeMatch_HitOnly only feeds banners whose port maps
// to the right category (expectedCategory hits). HS speed-up here comes
// purely from skipping non-matching probes inside that single category.
func BenchmarkServiceProbeMatch_HitOnly(b *testing.B) {
	if !loadRealProbes(b) {
		b.Skip("nmap-service-probes not found; install nmap to run this benchmark")
	}
	resetServiceProbeHSIndexForBench(b, true)

	hits := benchBanners[:9] // first 9 are the well-known-port hits
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bb := hits[i%len(hits)]
		s := benchService(bb.port, bb.proto)
		MatchServiceProbes(s, []byte(bb.banner), "bench")
	}
}

// BenchmarkServiceProbeMatch_HitOnly_NoHyperscan baseline for the above.
func BenchmarkServiceProbeMatch_HitOnly_NoHyperscan(b *testing.B) {
	if !loadRealProbes(b) {
		b.Skip("nmap-service-probes not found; install nmap to run this benchmark")
	}
	resetServiceProbeHSIndexForBench(b, false)

	hits := benchBanners[:9]
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bb := hits[i%len(hits)]
		s := benchService(bb.port, bb.proto)
		MatchServiceProbes(s, []byte(bb.banner), "bench")
	}
}

// BenchmarkServiceProbeMatch_MissOnly only feeds banners that don't fire
// any probe → matchProbes loops every probe of every category. Maximum
// fan-out, where HS multi-pattern wins are largest.
func BenchmarkServiceProbeMatch_MissOnly(b *testing.B) {
	if !loadRealProbes(b) {
		b.Skip("nmap-service-probes not found; install nmap to run this benchmark")
	}
	resetServiceProbeHSIndexForBench(b, true)

	misses := benchBanners[9:]
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bb := misses[i%len(misses)]
		s := benchService(bb.port, bb.proto)
		MatchServiceProbes(s, []byte(bb.banner), "bench")
	}
}

// BenchmarkServiceProbeMatch_MissOnly_NoHyperscan baseline for the above.
func BenchmarkServiceProbeMatch_MissOnly_NoHyperscan(b *testing.B) {
	if !loadRealProbes(b) {
		b.Skip("nmap-service-probes not found; install nmap to run this benchmark")
	}
	resetServiceProbeHSIndexForBench(b, false)

	misses := benchBanners[9:]
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bb := misses[i%len(misses)]
		s := benchService(bb.port, bb.proto)
		MatchServiceProbes(s, []byte(bb.banner), "bench")
	}
}
