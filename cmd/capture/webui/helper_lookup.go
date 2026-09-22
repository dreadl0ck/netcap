//go:build !appstore

/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package webui

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// helperName is the capture helper's filename for the running platform.
func helperName() string {
	if runtime.GOOS == "windows" {
		return "net.exe"
	}

	return "net"
}

// resolveHelperExecutable returns the path to the netcap capture helper.
//
// It prefers the copy shipped beside the caller over anything on PATH, because
// "net" is a name this binary does not own on two of three platforms:
// Windows has C:\Windows\System32\net.exe (the built-in network command) and
// Linux has Samba's /usr/bin/net. Resolving through PATH therefore depends on
// the GUI having prepended its own directory first, and when that ordering is
// wrong the failure is a capture helper that runs, rejects every argument and
// exits non-zero — which reads exactly like a netcap bug.
//
// Returns an empty string when no helper can be found, so the caller can say
// so instead of spawning something else under that name.
func resolveHelperExecutable() string {
	for _, candidate := range helperCandidates() {
		if isExecutableFile(candidate) {
			return candidate
		}
	}

	// Last resort: PATH. Anything inside the Windows directory is the
	// system's own net.exe and is never what we want.
	if found, err := exec.LookPath(helperName()); err == nil && !isSystemNetCommand(found) {
		return found
	}

	return ""
}

func helperCandidates() []string {
	execPath, err := os.Executable()
	if err != nil {
		return nil
	}

	if resolved, rerr := filepath.EvalSymlinks(execPath); rerr == nil {
		execPath = resolved
	}

	dir := filepath.Dir(execPath)

	return []string{
		// Alongside the GUI: the Windows installer, the portable ZIP and a
		// plain `go build` output all land here.
		filepath.Join(dir, helperName()),
		// macOS .app bundle: Contents/MacOS/<gui> -> Contents/Resources/bin/net.
		filepath.Join(dir, "..", "Resources", "bin", helperName()),
		// Linux package layout.
		filepath.Join("/usr", "lib", "netcap-pro", helperName()),
	}
}

func isExecutableFile(path string) bool {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}

	if runtime.GOOS == "windows" {
		return true
	}

	return info.Mode().Perm()&0o111 != 0
}

// isSystemNetCommand reports whether path is Windows' built-in net.exe.
func isSystemNetCommand(path string) bool {
	if runtime.GOOS != "windows" {
		return false
	}

	windir := os.Getenv("SystemRoot")
	if windir == "" {
		windir = os.Getenv("windir")
	}

	if windir == "" {
		windir = `C:\Windows`
	}

	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}

	return strings.HasPrefix(
		strings.ToLower(filepath.Clean(abs)),
		strings.ToLower(filepath.Clean(windir)),
	)
}
