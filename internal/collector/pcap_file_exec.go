//go:build !appstore

/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package collector

import (
	"os/exec"
	"strings"
)

// invokeFileCommand runs the system `file` binary on filePath and returns its
// one-line description, or "" if `file` is unavailable or fails. Used only to
// enrich the error message for a malformed capture.
//
// The App Sandbox forbids spawning binaries, so the appstore build replaces this
// with a no-op (pcap_file_appstore.go), which is also what keeps os/exec out of
// the collector package's App Store dependency graph.
func invokeFileCommand(filePath string) string {
	if _, err := exec.LookPath("file"); err != nil {
		return ""
	}
	output, err := exec.Command("file", "-b", filePath).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}
