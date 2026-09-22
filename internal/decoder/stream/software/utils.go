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

func makeSoftware(ts int64, product, website, sourceName, sourceData, flowIdent, communityID string) *AtomicSoftware {
	var communityIDs []string
	if communityID != "" {
		communityIDs = []string{communityID}
	}
	return &AtomicSoftware{
		Software: &types.Software{
			Timestamp:    ts,
			Product:      product,
			Notes:        "", // TODO: add info from implies field
			Website:      website,
			SourceName:   sourceName,
			SourceData:   sourceData,
			Service:      "HTTP",
			Flows:        []string{flowIdent},
			CommunityIDs: communityIDs,
		},
	}
}
