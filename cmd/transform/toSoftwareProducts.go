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
	netmaltego "github.com/dreadl0ck/netcap/maltego"
	"strings"

	"github.com/dreadl0ck/maltego"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
)

func toSoftwareProducts() {
	netmaltego.SoftwareTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, soft *types.Software, min, max uint64, path string, mac string, ipaddr string) {
			val := soft.Vendor + " " + soft.Product + " " + soft.Version
			if len(soft.SourceName) > 0 {
				if soft.SourceName == "Generic version harvester" {
					if len(val) == 0 {
						val = soft.SourceData
					} else {
						val += "\n" + soft.SourceData
					}
				}
				if len(soft.OS) > 0 {
					val += "\n" + soft.OS
				}
				val += "\n" + soft.SourceName
			}

			ent := addEntityWithPath(trx, "netcap.Software", val, path)
			ent.AddProperty("timestamp", "Timestamp", maltego.Strict, utils.UnixTimeToUTC(soft.Timestamp))
			ent.AddProperty("vendor", "Vendor", maltego.Strict, soft.Vendor)
			ent.AddProperty("product", "Product", maltego.Strict, soft.Product)
			ent.AddProperty("version", "Version", maltego.Strict, soft.Version)
			ent.AddProperty("flows", "Flows", maltego.Strict, strings.Join(soft.Flows, " | "))
			ent.AddProperty("sourcename", "SourceName", maltego.Strict, soft.SourceName)
			ent.AddProperty("sourcedata", "SourceData", maltego.Strict, soft.SourceData)
			ent.AddProperty("notes", "Notes", maltego.Strict, soft.Notes)

			ent.AddDisplayInformation(strings.Join(soft.Flows, "<br>"), "Flows")
		},
	)
}
