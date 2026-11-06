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
	"crypto/sha256"
	"debug/buildinfo"
	"debug/macho"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
)

// SetProductionHelperIdentity scopes strict packaged-helper lookup to Pro.
// Call once during startup, before starting the server. Empty identity fails closed.
func SetProductionHelperIdentity(version, revision string) {
	productionPro = true
	proHelperVersion, proHelperRevision = version, revision
}

var (
	productionPro     bool
	proHelperVersion  string
	proHelperRevision string
)

type helperManifest struct {
	Schema   int    `json:"schema"`
	Module   string `json:"module"`
	Version  string `json:"version"`
	Revision string `json:"revision"`
	SHA256   string `json:"sha256"`
}

// packagedHelperPath selects one layout, never a search list.
func packagedHelperPath(executable, platform string) string {
	dir := filepath.Dir(executable)
	if platform == "darwin" && filepath.Base(dir) == "MacOS" && filepath.Base(filepath.Dir(dir)) == "Contents" {
		return filepath.Join(dir, "..", "Resources", "bin", "net")
	}
	if platform == "linux" && (dir == "/usr/bin" || dir == "/usr/local/bin") {
		return "/usr/lib/netcap-pro/net"
	}
	name := "net"
	if platform == "windows" {
		name = "net.exe"
	}
	return filepath.Join(dir, name)
}

func verifyPackagedHelper(path, version, revision string) error {
	if version == "" || revision == "" {
		return fmt.Errorf("missing Pro helper build identity")
	}
	// Reject symlinks in the file and all parent directories.
	for p := path; ; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink in helper path: %s", p)
		}
		if p == path && !info.Mode().IsRegular() {
			return fmt.Errorf("helper is not a regular file")
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	if !isExecutableFile(path) {
		return fmt.Errorf("helper is not executable")
	}
	manifestPath := path + ".manifest.json"
	info, err := os.Lstat(manifestPath)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("helper manifest is not a regular file")
	}
	f, err := os.Open(manifestPath)
	if err != nil {
		return err
	}
	defer f.Close()
	var manifest helperManifest
	if err = json.NewDecoder(io.LimitReader(f, 16384)).Decode(&manifest); err != nil {
		return err
	}
	if manifest.Schema != 1 || manifest.Module != "github.com/dreadl0ck/netcap" || manifest.Version != version || manifest.Revision != revision {
		return fmt.Errorf("helper manifest build identity mismatch")
	}
	binary, err := os.Open(path)
	if err != nil {
		return err
	}
	defer binary.Close()
	hash := sha256.New()
	if _, err = io.Copy(hash, binary); err != nil {
		return err
	}
	if hex.EncodeToString(hash.Sum(nil)) != manifest.SHA256 {
		return fmt.Errorf("helper SHA-256 mismatch")
	}
	// Universal macOS helpers contain an independent Go build record per slice.
	fat, err := macho.NewFatFile(binary)
	if err != nil {
		build, readErr := buildinfo.Read(binary)
		if readErr != nil {
			return fmt.Errorf("helper build info: %w", readErr)
		}
		return verifyHelperBuild(build, version, revision)
	}
	for _, arch := range fat.Arches {
		build, err := buildinfo.Read(io.NewSectionReader(binary, int64(arch.Offset), int64(arch.Size)))
		if err != nil {
			return fmt.Errorf("helper slice build info: %w", err)
		}
		if err := verifyHelperBuild(build, version, revision); err != nil {
			return err
		}
	}
	return nil
}

func verifyHelperBuild(build *debug.BuildInfo, version, revision string) error {
	if build.Path != "github.com/dreadl0ck/netcap/cmd/net" || build.Main.Path != "github.com/dreadl0ck/netcap" {
		return fmt.Errorf("unexpected helper Go module or command")
	}
	var tags, flags string
	for _, setting := range build.Settings {
		if setting.Key == "-tags" {
			tags = setting.Value
		}
		if setting.Key == "-ldflags" {
			flags = setting.Value
		}
	}
	if !strings.Contains(","+tags+",", ",production,") ||
		!strings.Contains(" "+flags+" ", " -X github.com/dreadl0ck/netcap.Version="+version+" ") ||
		!strings.Contains(" "+flags+" ", " -X github.com/dreadl0ck/netcap.Commit="+revision+" ") {
		return fmt.Errorf("helper production build settings mismatch")
	}
	return nil
}

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
	if productionPro {
		executable, err := os.Executable()
		if err != nil {
			return ""
		}
		path := packagedHelperPath(executable, runtime.GOOS)
		if err := verifyPackagedHelper(path, proHelperVersion, proHelperRevision); err != nil {
			log.Printf("[Service] Packaged capture helper rejected: %v; reinstall Netcap Pro", err)
			return ""
		}
		return path
	}
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
