/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

// Implements primitives to resolve various identifiers against external data
package resolvers

type Config struct {
	ReverseDNS    bool
	LocalDNS      bool
	MACDB         bool
	Ja3DB         bool
	ServiceDB     bool
	GeolocationDB bool
}

var DefaultConfig = Config{
	ReverseDNS:    false,
	LocalDNS:      false,
	MACDB:         true,
	Ja3DB:         true,
	ServiceDB:     true,
	GeolocationDB: true,
}
