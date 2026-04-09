//go:build (!windows && ignore) || !nodpi

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

package dpi

// These variables can be set at build time using ldflags
// Example: -ldflags "-X github.com/dreadl0ck/netcap/dpi.NDPIVersion=4.14.0"
var (
	// NDPIVersion is the version of nDPI library linked against
	NDPIVersion = "unknown"

	// LibprotoidentVersion is the version of libprotoident library linked against
	LibprotoidentVersion = "unknown"

	// GoDPIVersion is the version of go-dpi wrapper used
	GoDPIVersion = "v1.4.1"
)

// GetVersionInfo returns a formatted string with DPI library versions
func GetVersionInfo() string {
	if NDPIVersion == "unknown" && LibprotoidentVersion == "unknown" {
		return "DPI support enabled (nDPI: runtime, libprotoident: runtime)"
	}
	return "DPI support enabled (nDPI: " + NDPIVersion + ", libprotoident: " + LibprotoidentVersion + ")"
}

// HasDPISupport returns true when DPI support is compiled in
func HasDPISupport() bool {
	return true
}
