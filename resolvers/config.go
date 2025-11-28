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

// Package resolvers implements primitives to resolve various identifiers against external data
package resolvers

// Config contains settings for the resolvers package.
type Config struct {

	// Controls whether ip addresses are resolved through the default OS resolver
	ReverseDNS bool

	// Controls if ip addresses are resolved locally through a provided hosts mapping
	LocalDNS bool

	// Enables MAC address vendor lookups
	MACDB bool

	// Enables looking up Ja3 profiles
	Ja3DB bool

	// Enables resolving port numbers to service names
	ServiceDB bool

	// Enables ip to geolocation lookups via MaxMind GeoLite
	GeolocationDB bool

	// Enables DHCP fingerprint lookups
	DHCPDB bool
}

// DefaultConfig is an example configuration.
var DefaultConfig = Config{
	ReverseDNS:    false,
	LocalDNS:      false,
	MACDB:         true,
	Ja3DB:         true,
	ServiceDB:     true,
	GeolocationDB: true,
	DHCPDB:        true,
}
