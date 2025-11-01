//go:build (!windows && ignore) || !nodpi
// +build !windows,ignore !nodpi

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

package dpi

// These variables can be set at build time using ldflags
// Example: -ldflags "-X github.com/dreadl0ck/netcap/dpi.NDPIVersion=4.14.0"
var (
	// NDPIVersion is the version of nDPI library linked against
	NDPIVersion = "unknown"

	// LibprotoidentVersion is the version of libprotoident library linked against
	LibprotoidentVersion = "unknown"

	// GoDPIVersion is the version of go-dpi wrapper used
	GoDPIVersion = "v1.3.0"
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
