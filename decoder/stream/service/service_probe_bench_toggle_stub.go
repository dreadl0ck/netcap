//go:build !hyperscan

/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package service

import "testing"

// resetServiceProbeHSIndexForBench is a no-op in stub builds: there is no
// HS index to toggle, and matchProbes will always take the RE2 path.
func resetServiceProbeHSIndexForBench(_ testing.TB, _ bool) {}
