//go:build appstore

/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package collector

// invokeFileCommand is a no-op in the App Store edition: the App Sandbox forbids
// spawning the system `file` binary, and this stub keeps os/exec out of the
// collector package entirely for the appstore build. The caller only uses the
// result to enrich a malformed-capture error message, which degrades to the
// generic message.
func invokeFileCommand(string) string { return "" }
