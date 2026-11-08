// Command licenses generates and verifies the third-party license bundle shipped with netcap.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

const defaultOutput = "legal/THIRD_PARTY_LICENSES.txt"

type module struct {
	Path    string
	Version string
	Dir     string
	Main    bool
	Replace *module
}

type goPackage struct {
	Dir      string
	Standard bool
	Module   *module
}

type dependency struct {
	Name     string
	Version  string
	License  string
	Paths    []string
	Variants map[string]bool
	Files    []licenseFile
	Replaced bool
}

type licenseFile struct {
	Name string
	Text string
}

type licenseReview struct {
	Module   string   `json:"module"`
	Version  string   `json:"version"`
	File     string   `json:"file"`
	SHA256   string   `json:"sha256"`
	Licenses []string `json:"licenses"`
	Reason   string   `json:"reason"`
}

type pnpmDependency struct {
	Name  string   `json:"name"`
	Paths []string `json:"paths"`
}

type packageMetadata struct {
	Version string `json:"version"`
}

type variant struct {
	name   string
	goos   string
	goarch string
	tags   string
}

var variants = []variant{
	{name: "linux-dpi", goos: "linux", goarch: "amd64"},
	{name: "linux-dpi-noyara", goos: "linux", goarch: "amd64", tags: "noyara"},
	{name: "linux-nodpi", goos: "linux", goarch: "amd64", tags: "nodpi,noyara"},
	{name: "darwin-dpi", goos: "darwin", goarch: "arm64"},
	{name: "darwin-nodpi", goos: "darwin", goarch: "arm64", tags: "nodpi"},
	{name: "windows-nodpi", goos: "windows", goarch: "amd64", tags: "nodpi,noyara"},
	{name: "linux-hyperscan", goos: "linux", goarch: "amd64", tags: "hyperscan,noyara"},
}

var allowedFrontendLicenses = map[string]bool{
	"0BSD": true, "Apache-2.0": true, "BSD-2-Clause": true, "BSD-3-Clause": true,
	"CC0-1.0": true, "ISC": true, "MIT": true, "OFL-1.1": true,
}

func main() {
	check := flag.Bool("check", false, "verify that the generated bundle is current")
	output := flag.String("output", defaultOutput, "bundle output path")
	flag.Parse()

	root, err := repositoryRoot()
	if err != nil {
		fatal(err)
	}

	deps, err := collectGoDependencies(root)
	if err != nil {
		fatal(err)
	}
	frontend, err := collectFrontendDependencies(root)
	if err != nil {
		fatal(err)
	}
	deps = append(deps, frontend...)

	bundle, err := render(deps)
	if err != nil {
		fatal(err)
	}
	outputPath := filepath.Join(root, *output)
	if *check {
		current, err := os.ReadFile(outputPath)
		if err != nil {
			fatal(fmt.Errorf("read generated bundle: %w", err))
		}
		if !bytes.Equal(current, bundle) {
			fatal(fmt.Errorf("%s is stale; run go run ./internal/tools/licenses", *output))
		}
		fmt.Printf("license bundle is current (%d dependencies)\n", len(deps))
		return
	}

	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		fatal(err)
	}
	if err := os.WriteFile(outputPath, bundle, 0o644); err != nil {
		fatal(err)
	}
	fmt.Printf("wrote %s (%d dependencies)\n", *output, len(deps))
}

func repositoryRoot() (string, error) {
	cmd := exec.Command("git", "rev-parse", "--show-toplevel")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("locate repository root: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

func collectGoDependencies(root string) ([]dependency, error) {
	reviewData, err := os.ReadFile(filepath.Join(root, "legal", "go-license-reviews.json"))
	if err != nil {
		return nil, err
	}
	var reviews []licenseReview
	if err := json.Unmarshal(reviewData, &reviews); err != nil {
		return nil, err
	}
	deps := make(map[string]*dependency)
	seenPackages := make(map[string]bool)
	for _, v := range variants {
		args := []string{"list", "-mod=readonly", "-deps", "-json"}
		if v.tags != "" {
			args = append(args, "-tags="+v.tags)
		}
		args = append(args, "./cmd/net")
		cmd := exec.Command("go", args...)
		cmd.Dir = root
		cmd.Env = append(os.Environ(), "GOWORK=off", "CGO_ENABLED=1", "GOOS="+v.goos, "GOARCH="+v.goarch)
		out, err := cmd.Output()
		if err != nil {
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				return nil, fmt.Errorf("list %s packages: %s", v.name, strings.TrimSpace(string(exitErr.Stderr)))
			}
			return nil, fmt.Errorf("list %s packages: %w", v.name, err)
		}

		decoder := json.NewDecoder(bytes.NewReader(out))
		for decoder.More() {
			var pkg goPackage
			if err := decoder.Decode(&pkg); err != nil {
				return nil, fmt.Errorf("decode %s package graph: %w", v.name, err)
			}
			if pkg.Standard || pkg.Module == nil || pkg.Module.Main {
				continue
			}
			mod := pkg.Module
			if mod.Replace != nil && mod.Replace.Version != "" {
				mod = mod.Replace
			}
			licenseDir := mod.Dir
			if mod.Replace != nil && mod.Replace.Dir != "" {
				licenseDir = mod.Replace.Dir
			}
			key := mod.Path + "@" + mod.Version
			dep := deps[key]
			if dep == nil {
				dep = &dependency{Name: mod.Path, Version: mod.Version, Replaced: mod.Replace != nil, Variants: make(map[string]bool)}
				deps[key] = dep
			}
			packageKey := key + "\x00" + pkg.Dir
			if !seenPackages[packageKey] {
				files, err := findLicenseFiles(pkg.Dir, licenseDir)
				if err != nil {
					return nil, fmt.Errorf("%s: %w", key, err)
				}
				if len(files) == 0 {
					return nil, fmt.Errorf("%s has no distributable license file", key)
				}
				dep.Files = mergeLicenseFiles(dep.Files, files)
				seenPackages[packageKey] = true
			}
			dep.Variants[v.name] = true
		}
	}

	if len(deps) == 0 {
		return nil, errors.New("production package graph contains no dependency modules")
	}
	result := make([]dependency, 0, len(deps))
	var policyErrors []error
	for _, dep := range deps {
		licenses, err := reviewedLicenses(dep, reviews)
		if err != nil {
			policyErrors = append(policyErrors, fmt.Errorf("%s@%s: %w", dep.Name, dep.Version, err))
			continue
		}
		dep.License = strings.Join(licenses, "; ")
		result = append(result, *dep)
	}
	slices.SortFunc(policyErrors, func(a, b error) int { return strings.Compare(a.Error(), b.Error()) })
	return result, errors.Join(policyErrors...)
}

func reviewedLicenses(dep *dependency, reviews []licenseReview) ([]string, error) {
	if len(dep.Files) == 0 {
		return nil, errors.New("no license files")
	}
	seenReviews := make(map[string]bool)
	for _, review := range reviews {
		if review.Module != dep.Name {
			continue
		}
		if dep.Replaced {
			return nil, errors.New("published-module license review does not cover a replacement")
		}
		if seenReviews[review.File] {
			return nil, fmt.Errorf("duplicate license review for %s", review.File)
		}
		seenReviews[review.File] = true
		if review.Version != dep.Version {
			return nil, fmt.Errorf("license review is stale for %s; review version %s", review.File, dep.Version)
		}
		if !slices.ContainsFunc(dep.Files, func(file licenseFile) bool { return file.Name == review.File }) {
			return nil, fmt.Errorf("reviewed legal file %s is missing", review.File)
		}
	}
	var licenses []string
	for _, file := range dep.Files {
		reviewed := false
		for _, review := range reviews {
			if review.Module != dep.Name || review.File != file.Name {
				continue
			}
			if review.Version != dep.Version || review.SHA256 != fmt.Sprintf("%x", sha256.Sum256([]byte(file.Text))) {
				return nil, fmt.Errorf("license review is stale for %s; review version and file content", file.Name)
			}
			if strings.TrimSpace(review.Reason) == "" || len(review.Licenses) == 0 {
				return nil, fmt.Errorf("incomplete license review for %s", file.Name)
			}
			licenses = append(licenses, review.Licenses...)
			reviewed = true
			break
		}
		if !reviewed {
			found, err := identifyLicenses([]licenseFile{file})
			if err != nil {
				return nil, fmt.Errorf("%s (sha256 %x): %w", file.Name, sha256.Sum256([]byte(file.Text)), err)
			}
			licenses = append(licenses, found...)
		}
	}
	slices.Sort(licenses)
	return slices.Compact(licenses), nil
}

func identifyLicenses(files []licenseFile) ([]string, error) {
	var licenses []string
	for _, file := range files {
		text := strings.ToLower(strings.Join(strings.Fields(file.Text), " "))
		for _, forbidden := range []string{"gnu affero general public license", "gnu general public license", "gnu lesser general public license", "gnu library general public license", "mozilla public license", "common development and distribution license", "gpl-", "agpl-", "lgpl-", "mpl-", "cddl-", "sspl-", "busl-", "cc-by-nc", "server side public license", "commons clause", "business source license", "non-commercial use only", "advertising materials", "foxio license", "nmap public source license"} {
			if strings.Contains(text, forbidden) {
				return nil, fmt.Errorf("forbidden or review-required license text %q in %s", forbidden, file.Name)
			}
		}
		before := len(licenses)
		switch {
		case strings.Contains(text, "sil open font license"):
			licenses = append(licenses, "OFL-1.1")
		case strings.Contains(text, "creative commons zero") || strings.Contains(text, "cc0 1.0"):
			licenses = append(licenses, "CC0-1.0")
		case strings.Contains(text, "the unlicense") || strings.Contains(text, "free and unencumbered software released into the public domain"):
			licenses = append(licenses, "Unlicense")
		case strings.Contains(text, "sqlite is public domain"):
			licenses = append(licenses, "public-domain")
		case strings.Contains(text, "zlib license") || strings.Contains(text, "this software is provided 'as-is', without any express or implied warranty"):
			licenses = append(licenses, "Zlib")
		default:
			if strings.Contains(text, "apache license") && strings.Contains(text, "version 2.0") {
				licenses = append(licenses, "Apache-2.0")
			}
			if strings.Contains(text, "permission is hereby granted, free of charge") {
				licenses = append(licenses, "MIT")
			}
			if strings.Contains(text, "redistribution and use in source and binary forms") {
				if strings.Contains(text, "neither the name") {
					licenses = append(licenses, "BSD-3-Clause")
				} else {
					licenses = append(licenses, "BSD-2-Clause")
				}
			}
			if strings.Contains(text, "permission to use, copy, modify, and/or distribute") {
				licenses = append(licenses, "ISC")
			}
		}
		if len(licenses) == before {
			return nil, fmt.Errorf("unrecognized license text in %s; explicit review required", file.Name)
		}
	}
	slices.Sort(licenses)
	licenses = slices.Compact(licenses)
	if len(licenses) == 0 {
		return nil, errors.New("could not identify license family")
	}
	return licenses, nil
}

func findLicenseFiles(packageDir, moduleDir string) ([]licenseFile, error) {
	packageDir, moduleDir = filepath.Clean(packageDir), filepath.Clean(moduleDir)
	rel, err := filepath.Rel(moduleDir, packageDir)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("package %s is outside module %s", packageDir, moduleDir)
	}
	dir := packageDir
	var result []licenseFile
	for {
		files, err := licenseFilesInDir(dir)
		if err != nil {
			return nil, err
		}
		for i := range files {
			rel, err := filepath.Rel(moduleDir, filepath.Join(dir, files[i].Name))
			if err != nil {
				return nil, err
			}
			files[i].Name = filepath.ToSlash(rel)
		}
		result = mergeLicenseFiles(result, files)
		if dir == moduleDir {
			return result, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir || !strings.HasPrefix(parent, moduleDir+string(filepath.Separator)) && parent != moduleDir {
			return nil, fmt.Errorf("package %s is outside module %s", packageDir, moduleDir)
		}
		dir = parent
	}
}

func licenseFilesInDir(dir string) ([]licenseFile, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var files []licenseFile
	for _, entry := range entries {
		if entry.IsDir() || !isLegalFile(entry.Name()) {
			continue
		}
		text, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, err
		}
		files = append(files, licenseFile{Name: entry.Name(), Text: strings.TrimSpace(string(text))})
	}
	slices.SortFunc(files, func(a, b licenseFile) int { return strings.Compare(a.Name, b.Name) })
	return files, nil
}

func isLegalFile(name string) bool {
	upper := strings.ToUpper(name)
	if strings.HasSuffix(upper, ".GO") {
		return false // e.g. lib/pq's notice.go implements database notices.
	}
	return strings.HasPrefix(upper, "LICENSE") || strings.HasPrefix(upper, "LICENCE") ||
		strings.HasPrefix(upper, "COPYING") || strings.HasPrefix(upper, "NOTICE")
}

func mergeLicenseFiles(first, second []licenseFile) []licenseFile {
	seen := make(map[string]bool)
	result := make([]licenseFile, 0, len(first)+len(second))
	for _, file := range append(first, second...) {
		key := file.Name + "\x00" + file.Text
		if !seen[key] {
			seen[key] = true
			result = append(result, file)
		}
	}
	return result
}

func collectFrontendDependencies(root string) ([]dependency, error) {
	frontendDir := filepath.Join(root, "cmd/capture/webui/frontend")
	cmd := exec.Command("pnpm", "licenses", "list", "--prod", "--json")
	cmd.Dir = frontendDir
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("list frontend licenses (run pnpm install --frozen-lockfile first): %w", err)
	}
	var byLicense map[string][]pnpmDependency
	if err := json.Unmarshal(out, &byLicense); err != nil {
		return nil, fmt.Errorf("decode frontend licenses: %w", err)
	}

	deps := make(map[string]dependency)
	for license, packages := range byLicense {
		if !allowedFrontendLicenses[license] {
			return nil, fmt.Errorf("frontend contains unreviewed license %q", license)
		}
		for _, pkg := range packages {
			if len(pkg.Paths) == 0 {
				return nil, fmt.Errorf("frontend package %s has no installed path", pkg.Name)
			}
			for _, path := range pkg.Paths {
				metadata, err := os.ReadFile(filepath.Join(path, "package.json"))
				if err != nil {
					return nil, fmt.Errorf("frontend package %s metadata: %w", pkg.Name, err)
				}
				var manifest packageMetadata
				if err := json.Unmarshal(metadata, &manifest); err != nil {
					return nil, fmt.Errorf("frontend package %s metadata: %w", pkg.Name, err)
				}
				if manifest.Version == "" {
					return nil, fmt.Errorf("frontend package %s has no version", pkg.Name)
				}
				key := pkg.Name + "@" + manifest.Version
				if _, exists := deps[key]; exists {
					continue
				}
				files, err := licenseFilesInDir(path)
				if err != nil {
					return nil, fmt.Errorf("frontend package %s: %w", key, err)
				}
				if len(files) == 0 {
					files = fallbackFrontendLicense(path, license)
				}
				if len(files) == 0 {
					return nil, fmt.Errorf("frontend package %s has no distributable license file", key)
				}
				deps[key] = dependency{
					Name: pkg.Name, Version: manifest.Version, License: license,
					Variants: map[string]bool{"webui": true}, Files: files,
				}
			}
		}
	}
	result := make([]dependency, 0, len(deps))
	for _, dep := range deps {
		result = append(result, dep)
	}
	return result, nil
}

func fallbackFrontendLicense(dir, license string) []licenseFile {
	switch license {
	case "CC0-1.0":
		return []licenseFile{{Name: "CC0-1.0", Text: "Package metadata dedicates this work to the public domain under CC0 1.0 Universal. Canonical terms: https://creativecommons.org/publicdomain/zero/1.0/legalcode.txt"}}
	case "MIT":
		var notices []string
		entries, _ := os.ReadDir(dir)
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
			if err != nil || len(data) > 1<<20 {
				continue
			}
			for _, line := range strings.Split(string(data), "\n") {
				if strings.Contains(strings.ToLower(line), "copyright") {
					notices = append(notices, strings.TrimSpace(strings.TrimLeft(line, "/*#; ")))
				}
			}
		}
		slices.Sort(notices)
		notices = slices.Compact(notices)
		if len(notices) == 0 {
			return nil
		}
		text := strings.Join(notices, "\n") + "\n\nPermission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the \"Software\"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:\n\nThe above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.\n\nTHE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE."
		return []licenseFile{{Name: "LICENSE (reconstructed from source notice and MIT terms)", Text: text}}
	default:
		return nil
	}
}

func render(deps []dependency) ([]byte, error) {
	sort.Slice(deps, func(i, j int) bool {
		if deps[i].Name == deps[j].Name {
			return deps[i].Version < deps[j].Version
		}
		return deps[i].Name < deps[j].Name
	})
	var out strings.Builder
	out.WriteString("NETCAP THIRD-PARTY LICENSES\n\n")
	out.WriteString("Generated by: go run ./internal/tools/licenses\n")
	out.WriteString("Do not edit this file manually. Build-specific native and copied-code notices are in THIRD_PARTY_NOTICES.txt.\n\n")
	out.WriteString("License inventories below describe collected texts, not alternative licensing grants. Component-specific terms and scope remain in the reproduced texts. This scan checks package/ancestor legal files; it is not a source-header or native-library audit.\n\n")
	for _, dep := range deps {
		variants := make([]string, 0, len(dep.Variants))
		for name := range dep.Variants {
			variants = append(variants, name)
		}
		slices.Sort(variants)
		fmt.Fprintf(&out, "================================================================================\n%s %s\nLicense inventory: %s\nUsed by: %s\n", dep.Name, dep.Version, dep.License, strings.Join(variants, ", "))
		if dep.Variants["webui"] {
			fmt.Fprintf(&out, "Source: https://www.npmjs.com/package/%s/v/%s\n", dep.Name, strings.Split(dep.Version, ", ")[0])
		} else {
			fmt.Fprintf(&out, "Source: https://pkg.go.dev/%s@%s\n", dep.Name, dep.Version)
		}
		files := slices.Clone(dep.Files)
		slices.SortFunc(files, func(a, b licenseFile) int {
			if c := strings.Compare(a.Name, b.Name); c != 0 {
				return c
			}
			return strings.Compare(a.Text, b.Text)
		})
		for _, file := range files {
			fmt.Fprintf(&out, "\n--- %s ---\n%s\n", file.Name, file.Text)
		}
		out.WriteByte('\n')
	}
	return []byte(out.String()), nil
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "license compliance:", err)
	os.Exit(1)
}
