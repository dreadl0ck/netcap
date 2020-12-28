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

package software

import "github.com/dreadl0ck/netcap/types"

// determine vendor name based on product name
// TODO: add more associations
func determineVendor(product string) (vendor string) {
	switch product {
	case "Chrome", "Android":
		vendor = "Google"
	case "Firefox":
		vendor = "Mozilla"
	case "Internet Explorer", "IE":
		vendor = "Microsoft"
	case "Safari", "iOS", "macOS":
		vendor = "Apple"
	}
	return vendor
}

func makeSoftware(ts int64, product, website, sourceName, sourceData, flowIdent string) *AtomicSoftware {
	return &AtomicSoftware{
		Software: &types.Software{
			Timestamp:  ts,
			Product:    product,
			Notes:      "", // TODO: add info from implies field
			Website:    website,
			SourceName: sourceName,
			SourceData: sourceData,
			Service:    "HTTP",
			Flows:      []string{flowIdent},
		},
	}
}
