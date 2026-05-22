/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package mcp

import "testing"

// TestUnifiedSessionLocalError pins a non-obvious semantic: when a local-
// mode file row carries an `error` field, the unified-session output
// must coerce its `status` to "failed". A future refactor that drops
// this coercion would silently leave failed sessions reported as
// "processing" forever.
func TestUnifiedSessionLocalError(t *testing.T) {
	in := map[string]any{
		"name":        "bad.pcap",
		"path":        "/data/bad.pcap",
		"isCompleted": false,
		"error":       "tcpdump exit 1",
	}
	out := unifiedSession("local", in)
	if got := out["status"]; got != "failed" {
		t.Errorf("status = %v, want \"failed\"", got)
	}
	if got := out["error"]; got != "tcpdump exit 1" {
		t.Errorf("error = %v", got)
	}
}
