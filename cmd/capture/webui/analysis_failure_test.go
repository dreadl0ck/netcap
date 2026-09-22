//go:build !appstore

/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package webui

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func writeLog(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), analysisErrorLogName)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write log: %v", err)
	}

	return path
}

// The reported case: the helper says exactly why it stopped, and the UI showed
// only the exit code.
func TestSummariseAnalysisFailureIncludesHelperMessage(t *testing.T) {
	path := writeLog(t, strings.Join([]string{
		"initializing netcap",
		`geolocation database not found: C:\Users\x\.config\netcap\dbs\GeoLite2-City.mmdb`,
	}, "\n"))

	got := summariseAnalysisFailure(errors.New("exit status 1"), path)

	if !strings.Contains(got, "exit status 1") {
		t.Errorf("summary dropped the exit status: %q", got)
	}
	if !strings.Contains(got, "GeoLite2-City.mmdb") {
		t.Errorf("summary dropped the helper's message: %q", got)
	}
}

// The summary block this package appends restates what the caller already
// knows. Echoing "Command: net capture ..." back as the cause would be worse
// than the exit code it replaced.
func TestSummariseAnalysisFailureSkipsItsOwnSummaryBlock(t *testing.T) {
	path := writeLog(t, strings.Join([]string{
		"panic: runtime error: index out of range",
		"",
		"=== Analysis Error Summary ===",
		"Input File: /tmp/a.pcap",
		"Output Directory: /tmp/out",
		"Duration: 1.2s",
		"Error: exit status 2",
		"Command: net capture -read /tmp/a.pcap",
		"",
	}, "\n"))

	got := summariseAnalysisFailure(errors.New("exit status 2"), path)

	if !strings.Contains(got, "panic: runtime error") {
		t.Errorf("summary did not reach past its own block: %q", got)
	}
	for _, banned := range []string{"Command:", "Output Directory:", "Duration:"} {
		if strings.Contains(got, banned) {
			t.Errorf("summary echoed its own %q line: %q", banned, got)
		}
	}
}

func TestSummariseAnalysisFailureWithoutLogIsStillUseful(t *testing.T) {
	got := summariseAnalysisFailure(errors.New("signal: killed"), "")

	if got != "Analysis failed: signal: killed" {
		t.Errorf("summary = %q", got)
	}
}

func TestSummariseAnalysisFailureHandlesMissingFile(t *testing.T) {
	got := summariseAnalysisFailure(errors.New("exit status 1"), filepath.Join(t.TempDir(), "absent.log"))

	if got != "Analysis failed: exit status 1" {
		t.Errorf("summary = %q", got)
	}
}

// Windows helpers write CRLF. Leaving the carriage return in makes the UI
// render a stray control character at the end of the message.
func TestSummariseAnalysisFailureHandlesCRLF(t *testing.T) {
	path := writeLog(t, "loading databases\r\ncould not open capture file\r\n")

	got := summariseAnalysisFailure(errors.New("exit status 1"), path)

	if strings.Contains(got, "\r") {
		t.Errorf("summary kept a carriage return: %q", got)
	}
	if !strings.HasSuffix(got, "could not open capture file") {
		t.Errorf("summary = %q", got)
	}
}

func TestSummariseAnalysisFailureTruncatesLongLines(t *testing.T) {
	path := writeLog(t, strings.Repeat("x", 5000))

	got := summariseAnalysisFailure(errors.New("exit status 1"), path)

	if len(got) > 400 {
		t.Errorf("summary is %d bytes, expected it to be truncated", len(got))
	}
	if !strings.HasSuffix(got, "…") {
		t.Errorf("truncated summary is not marked: %q", got)
	}
}

func TestSummariseAnalysisFailureIgnoresTrailingBlankLines(t *testing.T) {
	path := writeLog(t, "real failure line\n\n\n   \n")

	got := summariseAnalysisFailure(errors.New("exit status 1"), path)

	if !strings.HasSuffix(got, "real failure line") {
		t.Errorf("summary = %q", got)
	}
}

func TestHelperNameMatchesPlatform(t *testing.T) {
	want := "net"
	if runtime.GOOS == "windows" {
		want = "net.exe"
	}

	if got := helperName(); got != want {
		t.Errorf("helperName() = %q, want %q", got, want)
	}
}

// Windows' own net.exe accepts the name and rejects every argument, so
// resolving to it produces a usage error that reads like a netcap bug. Samba
// installs /usr/bin/net on Linux for the same reason this guard exists.
func TestIsSystemNetCommandOnlyMatchesOnWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Setenv("SystemRoot", `C:\Windows`)

		if !isSystemNetCommand(`C:\Windows\System32\net.exe`) {
			t.Error("failed to recognise the system net.exe")
		}
		if isSystemNetCommand(`C:\Program Files\Netcap Pro\net.exe`) {
			t.Error("rejected the bundled helper as a system command")
		}

		return
	}

	if isSystemNetCommand("/usr/bin/net") {
		t.Error("isSystemNetCommand must be a no-op off Windows")
	}
}

// The bundled helper must win over anything on PATH.
func TestHelperCandidatesPreferTheAdjacentBinary(t *testing.T) {
	candidates := helperCandidates()
	if len(candidates) == 0 {
		t.Fatal("no candidates")
	}

	self, err := os.Executable()
	if err != nil {
		t.Skipf("cannot resolve own executable: %v", err)
	}

	if resolved, rerr := filepath.EvalSymlinks(self); rerr == nil {
		self = resolved
	}

	want := filepath.Join(filepath.Dir(self), helperName())
	if candidates[0] != want {
		t.Errorf("first candidate = %q, want %q", candidates[0], want)
	}
}

// Truncation must not split a multi-byte rune, which would put U+FFFD in the
// message the user reads.
func TestSummariseAnalysisFailureTruncatesOnRuneBoundaries(t *testing.T) {
	path := writeLog(t, strings.Repeat("ü", 5000))

	got := summariseAnalysisFailure(errors.New("exit status 1"), path)

	if strings.ContainsRune(got, '\uFFFD') {
		t.Errorf("summary contains a replacement character: %q", got)
	}
	if !strings.HasSuffix(got, "…") {
		t.Errorf("truncated summary is not marked: %q", got)
	}
}
