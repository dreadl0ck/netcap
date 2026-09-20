package netcap

import (
	"slices"
	"testing"
)

func TestBundledLicenses(t *testing.T) {
	expected := []string{
		"LICENSE",
		"legal/THIRD_PARTY_LICENSES.txt",
		"legal/THIRD_PARTY_NOTICES.txt",
		"legal/THIRD_PARTY_RUST_LICENSES.txt",
		"legal/licenses/JA4-BSD-3-Clause.txt",
		"legal/licenses/LGPL-3.0.txt",
	}
	if names := LicenseNames(); !slices.Equal(names, expected) {
		t.Fatalf("LicenseNames() = %v, want %v", names, expected)
	}
	for _, name := range expected {
		text, err := ReadLicense(name)
		if err != nil {
			t.Fatalf("ReadLicense(%q): %v", name, err)
		}
		if len(text) == 0 {
			t.Fatalf("ReadLicense(%q) returned an empty document", name)
		}
	}
}

func TestReadLicenseRejectsUnknownPaths(t *testing.T) {
	for _, name := range []string{"missing.txt", "../LICENSE", "legal/../LICENSE"} {
		if _, err := ReadLicense(name); err == nil {
			t.Fatalf("ReadLicense(%q) succeeded", name)
		}
	}
}
