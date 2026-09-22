//go:build !nomagika

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

package magika

// MagikaVersion is the version of the Magika CLI (set at build time via ldflags)
var MagikaVersion = "1.0.2"

// GetVersionInfo returns a formatted string with Magika version info
func GetVersionInfo() string {
	return "Magika support enabled (CLI v" + MagikaVersion + ")"
}

// HasMagikaSupport returns true when Magika support is compiled in
func HasMagikaSupport() bool {
	return true
}
