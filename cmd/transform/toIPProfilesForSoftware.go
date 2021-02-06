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

package transform

import (
	"github.com/dreadl0ck/maltego"
	netmaltego "github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
)

func toIPProfilesForSoftware() {
	var (
		product string
		version string
		vendor  string
		p       = netmaltego.LoadIPProfiles()
		ips     = make(map[string]struct{})
	)
	netmaltego.SoftwareTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, soft *types.Software, min, max uint64, path string, mac string, ipaddr string) {
			if product == "" && vendor == "" {
				product = lt.Values["product"]
				version = lt.Values["version"]
				vendor = lt.Values["vendor"]
				if product == "" && vendor == "" && version == "" {
					maltego.Die("product, vendor and version are not set in properties!", "")
				}
			}

			if soft.Vendor == vendor && soft.Product == product && soft.Version == version {
				for _, f := range soft.Flows {
					srcIP, _, dstIP, _ := utils.ParseFlowIdent(f)

					// check if srcIP host has already been added
					if _, ok := ips[srcIP]; !ok {
						if profile, exists := p[srcIP]; exists {
							addIPProfile(trx, profile, path, min, max)
						}
						ips[srcIP] = struct{}{}
					}

					// check if dstIP host has already been added
					if _, ok := ips[dstIP]; !ok {
						if profile, exists := p[dstIP]; exists {
							addIPProfile(trx, profile, path, min, max)
						}
						ips[dstIP] = struct{}{}
					}
				}
			}
		},
	)
}
