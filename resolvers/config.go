/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017-2020 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
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
}

// DefaultConfig is an example configuration.
var DefaultConfig = Config{
	ReverseDNS:    false,
	LocalDNS:      false,
	MACDB:         true,
	Ja3DB:         true,
	ServiceDB:     true,
	GeolocationDB: true,
}
