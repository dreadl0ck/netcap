//go:build integration

package integration_tests

import (
	"os"
	"testing"
)

// requireFixture skips the calling test when path is absent, or fails when
// NETCAP_REQUIRE_FIXTURES is set.
//
// Skipping is the default because most of this suite's corpus is untracked:
// .gitignore's "*.pcap" and "*/*.pcap" exclude testdata/{test,cip,s7comm_*}.pcap
// and three of the five QUIC captures, so a clean checkout does not have them
// and a developer without the corpus would otherwise be unable to run anything.
//
// The cost of that default is that a missing fixture is indistinguishable from
// a passing suite: measured on 2026-09-22, removing the six untracked captures
// took this package from 5 skips to 8 and it still exited 0. Set
// NETCAP_REQUIRE_FIXTURES=1 wherever the suite is expected to actually run, so
// an absent capture is reported instead of quietly reducing coverage.
//
// Mirrors the NETCAP_REQUIRE_ULTIMATE_PCAP gate in
// collector/ultimate_pcap_test.go:40.
func requireFixture(tb testing.TB, path string) {
	tb.Helper()

	if _, err := os.Stat(path); err != nil {
		if os.Getenv("NETCAP_REQUIRE_FIXTURES") != "" {
			tb.Fatalf("required fixture %s is not available: %v", path, err)
		}

		tb.Skipf("fixture %s not available (%v); set NETCAP_REQUIRE_FIXTURES=1 to make this fail", path, err)
	}
}
