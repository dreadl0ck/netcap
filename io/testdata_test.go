/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package io

import (
	"os"
	"testing"
)

// testAuditRecord is the fixture the reader and dump tests decode.
const testAuditRecord = "../tests/testdata/TCP.ncap.gz"

// requireTestAuditRecord skips the calling test unless the fixture exists.
//
// tests/ is almost entirely gitignored ("tests/*", with two exceptions), so
// this file is present only on machines where a capture has been run before.
// Without the guard these tests fail on any clean checkout and in CI with a
// bare "no such file or directory", which reads like a code fault rather than
// a missing fixture.
func requireTestAuditRecord(t *testing.T) {
	t.Helper()

	if _, err := os.Stat(testAuditRecord); err != nil {
		t.Skipf("audit record fixture %s not available (%v); "+
			"generate it by running a capture into tests/testdata", testAuditRecord, err)
	}
}
