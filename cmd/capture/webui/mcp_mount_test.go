/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package webui

import "testing"

// TestLoopbackize covers the host-rewrite edge cases that matter for the
// `/mcp` mount: empty host, 0.0.0.0, IPv6 unspecified, malformed input.
func TestLoopbackize(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"http://0.0.0.0:8080", "http://127.0.0.1:8080"},
		{"http://[::]:8080", "http://127.0.0.1:8080"},
		{"http://:8080", "http://127.0.0.1:8080"},
		{"http://127.0.0.1:60590", "http://127.0.0.1:60590"},
		{"http://localhost:8080", "http://localhost:8080"},
		{"http://10.0.0.1:8080", "http://10.0.0.1:8080"},
		{"https://example.com:443", "https://example.com:443"}, // non-http: passthrough
		{"garbage", "garbage"},                                 // no scheme: passthrough
	}
	for _, c := range cases {
		if got := loopbackize(c.in); got != c.want {
			t.Errorf("loopbackize(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
