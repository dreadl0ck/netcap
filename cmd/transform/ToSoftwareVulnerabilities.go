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

func toSoftwareVulnerabilities() {
	netmaltego.VulnerabilityTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, vuln *types.Vulnerability, min, max uint64, path string, mac string, ipaddr string) {
			val := vuln.ID

			if vuln.Software != nil {
				vendor := vuln.Software.Vendor
				if len(vendor) > 0 {
					vendor += " "
				}
				product := vendor + vuln.Software.Product + " / " + vuln.Software.Version
				if len(vuln.Software.OS) > 0 {
					product += "\n" + vuln.Software.OS
				}
				val += "\n" + product
			}

			ent := addEntityWithPath(trx, "netcap.Vulnerability", val, path)
			ent.AddProperty("timestamp", "Timestamp", maltego.Strict, utils.UnixTimeToUTC(vuln.Timestamp))
			ent.AddProperty("id", "ID", maltego.Strict, vuln.ID)
			ent.AddProperty("notes", "Notes", maltego.Strict, vuln.Notes)
			ent.AddProperty("flows", "Flows", maltego.Strict, strings.Join(vuln.Software.Flows, " | "))
			ent.AddProperty("software", "Software", maltego.Strict, vuln.Software.Product+" "+vuln.Software.Version)

			ent.AddDisplayInformation(vuln.Description, "Description")
			ent.AddDisplayInformation(strings.Join(vuln.Software.Flows, "<br>"), "Flows")
		},
	)
}
