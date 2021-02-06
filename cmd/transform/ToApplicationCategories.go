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
	"strconv"

	"github.com/dreadl0ck/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func toApplicationCategories() {
	netmaltego.IPProfileTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, profile *types.IPProfile, min, max uint64, path string, mac string, ipaddr string) {
			if ipaddr == "" {
				ipaddr = lt.Values[netmaltego.PropertyIpAddr]
				if ipaddr == "" {
					maltego.Die("ipaddr property not set", "")
				}
			}
			toCategory(profile, mac, path, trx)
		},
	)
}

func toCategory(p *types.IPProfile, mac, path string, trx *maltego.Transform) {
	for _, proto := range p.Protocols {
		if proto.Category == "" {
			continue
		}

		ent := addEntityWithPath(trx, "netcap.ApplicationCategory", proto.Category, path)
		ent.AddProperty("mac", "MacAddress", maltego.Strict, mac)
		ent.SetLinkLabel(strconv.FormatInt(int64(proto.Packets), 10) + " pkts")
	}
}
