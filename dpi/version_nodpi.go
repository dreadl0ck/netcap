//go:build nodpi

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

var (
	// NDPIVersion is not applicable when DPI is disabled
	NDPIVersion = ""

	// LibprotoidentVersion is not applicable when DPI is disabled
	LibprotoidentVersion = ""

	// GoDPIVersion is not applicable when DPI is disabled
	GoDPIVersion = ""
)

// GetVersionInfo returns a message indicating DPI is not supported
func GetVersionInfo() string {
	return "DPI support disabled"
}

// HasDPISupport returns false when DPI support is not compiled in
func HasDPISupport() bool {
	return false
}
