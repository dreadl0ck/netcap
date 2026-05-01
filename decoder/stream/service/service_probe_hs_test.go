//go:build hyperscan

/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package service

import (
	"regexp"
	"testing"
	"time"

	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
)

// installSyntheticProbes builds a tiny in-memory probe set so the Hyperscan
// fast path can be exercised without depending on the on-disk
// nmap-service-probes file (which the regular TestClassifyBanners test
// requires + skips when missing).
//
// Probes are crafted so each banner matches exactly one probe – verifying
// that:
//   - the HS prefilter does not drop legitimate hits, and
//   - probes that should NOT match are skipped (i.e. the fast path is doing
//     real work, not just behaving like a no-op).
func installSyntheticProbes(t *testing.T) (cleanup func()) {
	t.Helper()

	prevConfig := decoderconfig.Instance
	decoderconfig.Instance = decoderconfig.DefaultConfig
	decoderconfig.Instance.UseRE2 = true

	prevProbes := serviceProbes
	prevPortsTCP := servicesByPortsTCP

	serviceProbes = map[string][]*serviceProbe{
		"ftp": {
			{
				Ident:    "ftp-vsftpd",
				RegEx:    regexp.MustCompile(`^220 \(vsFTPd ([\d.]+)\)`),
				RegExRaw: `^220 \(vsFTPd ([\d.]+)\)`,
				Product:  "vsFTPd",
				Version:  "$1",
			},
			{
				Ident:    "ftp-proftpd",
				RegEx:    regexp.MustCompile(`^220 ProFTPD ([\d.]+)`),
				RegExRaw: `^220 ProFTPD ([\d.]+)`,
				Product:  "ProFTPD",
				Version:  "$1",
			},
			{
				Ident:    "ftp-pureftpd",
				RegEx:    regexp.MustCompile(`^220.*Pure-FTPd`),
				RegExRaw: `^220.*Pure-FTPd`,
				Product:  "Pure-FTPd",
			},
		},
	}
	servicesByPortsTCP = map[int32]string{21: "ftp"}

	buildServiceProbeHSIndex()

	return func() {
		serviceProbeHSIndexMu.Lock()
		for _, c := range serviceProbeHSIndex {
			_ = c.db.Close()
		}
		serviceProbeHSIndex = make(map[string]*serviceProbeHSCategory)
		serviceProbeHSIndexMu.Unlock()

		serviceProbes = prevProbes
		servicesByPortsTCP = prevPortsTCP
		decoderconfig.Instance = prevConfig
	}
}

func TestHyperscanFastPath_MatchesExpectedProbe(t *testing.T) {
	cleanup := installSyntheticProbes(t)
	defer cleanup()

	if len(serviceProbeHSIndex) != 1 {
		t.Fatalf("expected 1 HS category, got %d", len(serviceProbeHSIndex))
	}

	serv := NewService(time.Now().UnixNano(), 0, 0, "")
	serv.IP = "127.0.0.1"
	serv.Port = 21
	serv.Protocol = "TCP"
	ident := "127.0.0.1:4322->127.0.0.1:21"
	serv.Flows = []string{ident}

	MatchServiceProbes(serv, []byte("220 (vsFTPd 3.0.3)\r\n"), ident)

	if serv.Product != "vsFTPd" {
		t.Fatalf("expected Product=vsFTPd, got %q", serv.Product)
	}
	if serv.Version != "3.0.3" {
		t.Fatalf("expected Version=3.0.3, got %q", serv.Version)
	}
	if serv.MatchedProbeID != "ftp-vsftpd" {
		t.Fatalf("expected MatchedProbeID=ftp-vsftpd, got %q", serv.MatchedProbeID)
	}
}

func TestHyperscanFastPath_PrefilterRulesOut(t *testing.T) {
	cleanup := installSyntheticProbes(t)
	defer cleanup()

	serv := NewService(time.Now().UnixNano(), 0, 0, "")
	serv.IP = "127.0.0.1"
	serv.Port = 21
	serv.Protocol = "TCP"
	ident := "127.0.0.1:4322->127.0.0.1:21"
	serv.Flows = []string{ident}

	// A banner that none of the synthetic probes match: the HS DB returns
	// zero hits and matchProbes must therefore not set any product.
	MatchServiceProbes(serv, []byte("HELLO this is not an FTP banner\r\n"), ident)

	if serv.Product != "" {
		t.Fatalf("expected empty Product, got %q", serv.Product)
	}
	if serv.MatchedProbeID != "" {
		t.Fatalf("expected empty MatchedProbeID, got %q", serv.MatchedProbeID)
	}
}

func TestHyperscanFastPath_CandidatesNilWhenDisabled(t *testing.T) {
	prev := decoderconfig.Instance
	decoderconfig.Instance = decoderconfig.DefaultConfig
	decoderconfig.Instance.UseRE2 = false
	defer func() { decoderconfig.Instance = prev }()

	if cands := hsCandidatesForCategory("ftp", []*serviceProbe{{Ident: "x"}}, []byte("data")); cands != nil {
		t.Fatalf("expected nil candidates with UseRE2=false, got %v", cands)
	}
}

func TestHyperscanFastPath_CandidatesNilWhenCategoryUnknown(t *testing.T) {
	cleanup := installSyntheticProbes(t)
	defer cleanup()

	if cands := hsCandidatesForCategory("unknown-category", []*serviceProbe{{Ident: "x"}}, []byte("data")); cands != nil {
		t.Fatalf("expected nil for unknown category, got %v", cands)
	}
}

func TestHyperscanFastPath_RejectedProbeStillEvaluated(t *testing.T) {
	// A probe whose RegExRaw uses a Hyperscan-unsupported feature
	// (backreference) must still match through the linear RE2 path.
	prevConfig := decoderconfig.Instance
	decoderconfig.Instance = decoderconfig.DefaultConfig
	decoderconfig.Instance.UseRE2 = true

	prevProbes := serviceProbes
	prevPortsTCP := servicesByPortsTCP

	// Note: RE2 in Go does NOT support backreferences either, so to model
	// "HS rejects but RE2 accepts", we use a backreference-like construct
	// that gohs rejects but Go's RE2 happens to parse: lookahead `(?=...)`
	// is RE2-incompatible too, so we use a different angle – just supply
	// an HS-rejected expression and a no-op RE2-compatible RegEx that
	// still matches the banner. The point is that the fall-back kicks in.
	serviceProbes = map[string][]*serviceProbe{
		"weird": {
			{
				Ident:    "always-match",
				RegEx:    regexp.MustCompile(`^banner$`),
				RegExRaw: `(\w+)\1`, // backreference – HS will reject this
				Product:  "AlwaysMatch",
			},
		},
	}
	servicesByPortsTCP = map[int32]string{1234: "weird"}
	buildServiceProbeHSIndex()
	defer func() {
		serviceProbeHSIndexMu.Lock()
		for _, c := range serviceProbeHSIndex {
			_ = c.db.Close()
		}
		serviceProbeHSIndex = make(map[string]*serviceProbeHSCategory)
		serviceProbeHSIndexMu.Unlock()

		serviceProbes = prevProbes
		servicesByPortsTCP = prevPortsTCP
		decoderconfig.Instance = prevConfig
	}()

	serv := NewService(time.Now().UnixNano(), 0, 0, "")
	serv.IP = "127.0.0.1"
	serv.Port = 1234
	serv.Protocol = "TCP"
	ident := "127.0.0.1:5555->127.0.0.1:1234"
	serv.Flows = []string{ident}

	MatchServiceProbes(serv, []byte("banner"), ident)

	if serv.Product != "AlwaysMatch" {
		t.Fatalf("expected fallback to evaluate rejected probe via RE2, got Product=%q", serv.Product)
	}
}

func TestHyperscanStatus_ReflectsBuild(t *testing.T) {
	cleanup := installSyntheticProbes(t)
	defer cleanup()

	st := GetHyperscanStatus()
	if !st.Enabled {
		t.Fatal("expected Status.Enabled=true under the hyperscan tag")
	}
	if st.LibVersion == "" || st.LibVersion == "disabled" {
		t.Errorf("expected non-empty libhs version, got %q", st.LibVersion)
	}
	if st.Build.Categories != 1 {
		t.Errorf("expected 1 category in build stats, got %d", st.Build.Categories)
	}
	if st.Build.PatternsHS != 3 {
		t.Errorf("expected 3 patterns_hyperscan, got %d", st.Build.PatternsHS)
	}
	if len(st.Categories) != 1 {
		t.Fatalf("expected 1 category in status, got %d", len(st.Categories))
	}
	if st.Categories[0].Name != "ftp" {
		t.Errorf("expected category name 'ftp', got %q", st.Categories[0].Name)
	}
}
