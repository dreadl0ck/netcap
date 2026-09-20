package netcap

import (
	"embed"
	"fmt"
	"slices"
)

//go:embed LICENSE legal/*.txt legal/licenses/*.txt
var bundledLicenses embed.FS

var bundledLicenseNames = []string{
	"LICENSE",
	"legal/THIRD_PARTY_LICENSES.txt",
	"legal/THIRD_PARTY_NOTICES.txt",
	"legal/THIRD_PARTY_RUST_LICENSES.txt",
	"legal/licenses/JA4-BSD-3-Clause.txt",
	"legal/licenses/LGPL-3.0.txt",
}

// LicenseNames returns the paths of all license documents embedded in Netcap.
func LicenseNames() []string {
	return slices.Clone(bundledLicenseNames)
}

// ReadLicense returns an embedded license document by its listed path.
func ReadLicense(name string) ([]byte, error) {
	if !slices.Contains(bundledLicenseNames, name) {
		return nil, fmt.Errorf("unknown bundled license %q", name)
	}
	return bundledLicenses.ReadFile(name)
}
