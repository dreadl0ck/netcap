//go:build nodpi
// +build nodpi

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
