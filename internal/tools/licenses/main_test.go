package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const mitGrant = "Permission is hereby granted, free of charge, to any person obtaining a copy of this software"
const bsdGrant = "Redistribution and use in source and binary forms are permitted. Neither the name of the copyright holder nor contributors may endorse products."

func TestUnreviewedRestrictedLicensesFail(t *testing.T) {
	for _, text := range []string{
		"GNU GENERAL PUBLIC LICENSE Version 3",
		"GNU GENERAL\nPUBLIC LICENSE Version 2",
		"GNU LESSER GENERAL PUBLIC LICENSE",
		"GNU AFFERO GENERAL PUBLIC LICENSE",
		"SPDX-License-Identifier: GPL-3.0-only",
		"SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1",
		"Mozilla Public License, version 2.0",
		"Common Development and Distribution License",
		"Business Source License",
		"SPDX-License-Identifier: CC-BY-NC-4.0",
		"Nmap Public Source License",
	} {
		for _, name := range []string{"LICENSE", "NOTICE", "subdir/COPYING"} {
			t.Run(name+"/"+text, func(t *testing.T) {
				// A permissive grant elsewhere must not mask the restricted text.
				_, err := identifyLicenses([]licenseFile{{Name: name, Text: mitGrant + "\n" + text}})
				if err == nil {
					t.Fatal("unreviewed restricted text was accepted")
				}
			})
		}
	}
}

func TestUnknownLegalFileCannotHideBehindMIT(t *testing.T) {
	_, err := identifyLicenses([]licenseFile{
		{Name: "LICENSE", Text: mitGrant},
		{Name: "LICENSE-extra", Text: "Custom terms: permission requires contacting the author."},
	})
	if err == nil {
		t.Fatal("unknown legal file was silently omitted")
	}
}

func TestMixedInventoryDoesNotGrantAlternativeLicenses(t *testing.T) {
	families, err := identifyLicenses([]licenseFile{{Name: "LICENSE", Text: mitGrant + "\n" + bsdGrant}})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(families, []string{"BSD-3-Clause", "MIT"}) {
		t.Fatalf("mixed license text inventory = %v", families)
	}
	data, err := render([]dependency{{Name: "example.org/library", Version: "v1.0.0", License: strings.Join(families, "; ")}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "BSD-3-Clause OR MIT") || !strings.Contains(string(data), "License inventory: BSD-3-Clause; MIT") {
		t.Fatalf("rendered an incorrect license expression: %s", data)
	}
}

func TestReviewIsBoundToModuleVersionPathAndContent(t *testing.T) {
	file := licenseFile{Name: "LICENSE", Text: "Mozilla Public License, version 2.0"}
	review := licenseReview{
		Module: "example.org/library", Version: "v1.0.0", File: file.Name,
		SHA256:   fmt.Sprintf("%x", sha256.Sum256([]byte(file.Text))),
		Licenses: []string{"MPL-2.0"}, Reason: "Unmodified covered source is supplied with notices.",
	}
	base := dependency{Name: review.Module, Version: review.Version, Files: []licenseFile{file}}
	if got, err := reviewedLicenses(&base, []licenseReview{review}); err != nil || !slices.Equal(got, []string{"MPL-2.0"}) {
		t.Fatalf("valid review: %v, %v", got, err)
	}
	for _, test := range []struct {
		name string
		edit func(*dependency)
	}{
		{"module", func(d *dependency) { d.Name = "example.org/other" }},
		{"replacement", func(d *dependency) { d.Replaced = true }},
		{"version", func(d *dependency) { d.Version = "v1.0.1" }},
		{"path", func(d *dependency) { d.Files[0].Name = "other/LICENSE" }},
		{"content", func(d *dependency) { d.Files[0].Text += " Changed terms" }},
		{"missing", func(d *dependency) { d.Files = []licenseFile{{Name: "LICENSE-new", Text: mitGrant}} }},
		{"extra-gpl", func(d *dependency) {
			d.Files = append(d.Files, licenseFile{Name: "COPYING", Text: "GNU GENERAL PUBLIC LICENSE"})
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			d := base
			d.Files = slices.Clone(base.Files)
			test.edit(&d)
			if _, err := reviewedLicenses(&d, []licenseReview{review}); err == nil {
				t.Fatal("review accepted changed identity or content")
			}
		})
	}
	if _, err := reviewedLicenses(&base, []licenseReview{review, review}); err == nil {
		t.Fatal("duplicate review accepted")
	}
	review.Reason = ""
	if _, err := reviewedLicenses(&base, []licenseReview{review}); err == nil {
		t.Fatal("review without rationale accepted")
	}
}

func TestCollectEveryAncestorAndPackageLegalFile(t *testing.T) {
	root := t.TempDir()
	write := func(name, text string) {
		t.Helper()
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("LICENSE", mitGrant)
	write("sub/LICENSE", bsdGrant)
	write("sub/pkg/NOTICE", "package attribution")
	write("other/COPYING", "GNU GENERAL PUBLIC LICENSE Version 3")
	first, err := findLicenseFiles(filepath.Join(root, "sub/pkg"), root)
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, f := range first {
		paths = append(paths, f.Name)
	}
	slices.Sort(paths)
	if !slices.Equal(paths, []string{"LICENSE", "sub/LICENSE", "sub/pkg/NOTICE"}) {
		t.Fatalf("missing or incorrectly named ancestor files: %v", paths)
	}
	second, err := findLicenseFiles(filepath.Join(root, "other"), root)
	if err != nil {
		t.Fatal(err)
	}
	merged := mergeLicenseFiles(first, second)
	if len(merged) != 4 {
		t.Fatalf("lost sibling license or duplicated root license: %v", merged)
	}
	if _, err := identifyLicenses(second); err == nil {
		t.Fatal("sibling GPL file was accepted")
	}
	if _, err := findLicenseFiles(root+"-outside", root); err == nil {
		t.Fatal("accepted directory outside module")
	}
}

func TestRenderLegalFilesDeterministically(t *testing.T) {
	d := dependency{Name: "example.org/library", Files: []licenseFile{{Name: "sub/LICENSE", Text: bsdGrant}, {Name: "LICENSE", Text: mitGrant}}}
	a, err := render([]dependency{d})
	if err != nil {
		t.Fatal(err)
	}
	slices.Reverse(d.Files)
	b, err := render([]dependency{d})
	if err != nil || string(a) != string(b) {
		t.Fatalf("legal file traversal changed rendered output: %v", err)
	}
}

func TestModerncReviewBuildScope(t *testing.T) {
	// FOSSA dispositions cover these exact targets/tags, not arbitrary source builds.
	want := []variant{
		{"linux-dpi", "linux", "amd64", ""},
		{"linux-dpi-noyara", "linux", "amd64", "noyara"},
		{"linux-nodpi", "linux", "amd64", "nodpi,noyara"},
		{"darwin-dpi", "darwin", "arm64", ""},
		{"darwin-nodpi", "darwin", "arm64", "nodpi"},
		{"windows-nodpi", "windows", "amd64", "nodpi,noyara"},
		{"linux-hyperscan", "linux", "amd64", "hyperscan,noyara"},
	}
	if !slices.Equal(variants, want) {
		t.Fatal("build scope changed: re-review modernc headers and FOSSA dispositions before updating this assertion")
	}
}
