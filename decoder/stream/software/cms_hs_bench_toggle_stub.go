//go:build !hyperscan

/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package software

import "testing"

// resetCMSHSIndexForBench is a no-op in stub builds.
func resetCMSHSIndexForBench(_ testing.TB, _ bool) {}
