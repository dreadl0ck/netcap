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
	"fmt"
	netmaltego "github.com/dreadl0ck/netcap/maltego"
	"html"
	"strconv"

	"github.com/dustin/go-humanize"

	"github.com/dreadl0ck/maltego"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
)

func toServices() {
	var typ string
	netmaltego.ServiceTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, service *types.Service, min, max uint64, path string, mac string, ipaddr string) {
			if typ == "" {
				typ = lt.Values["properties.servicetype"]
				if typ == "" {
					maltego.Die("properties.servicetype not set", fmt.Sprint(lt.Values))
				}
			}

			if service.Name == typ {
				val := service.IP + ":" + strconv.Itoa(int(service.Port))
				if len(service.Vendor) > 0 {
					val += "\n" + service.Vendor
				}
				if len(service.Product) > 0 {
					val += "\n" + service.Product
				}
				//if len(service.Name) > 0 {
				//	val += "\n" + service.Name
				//}
				if len(service.Hostname) > 0 {
					val += "\n" + service.Hostname
				}

				ent := addEntityWithPath(trx, "netcap.Service", val, path)
				ent.AddProperty("timestamp", "Timestamp", maltego.Strict, utils.UnixTimeToUTC(service.Timestamp))
				ent.AddProperty("product", "Product", maltego.Strict, service.Product)
				ent.AddProperty("version", "Version", maltego.Strict, service.Version)
				ent.AddProperty("protocol", "Protocol", maltego.Strict, service.Protocol)
				ent.AddProperty("ip", "IP", maltego.Strict, service.IP)
				ent.AddProperty("port", "Port", maltego.Strict, strconv.Itoa(int(service.Port)))
				ent.AddProperty("hostname", "Hostname", maltego.Strict, service.Hostname)
				ent.AddProperty("bytesclient", "BytesClient", maltego.Strict, strconv.Itoa(int(service.BytesClient)))
				ent.AddProperty("bytesserver", "BytesServer", maltego.Strict, strconv.Itoa(int(service.BytesServer)))
				ent.AddProperty("vendor", "Vendor", maltego.Strict, service.Vendor)
				ent.AddProperty("name", "Name", maltego.Strict, service.Name)

				ent.SetLinkLabel(humanize.Bytes(uint64(service.BytesServer)) + " server\n" + humanize.Bytes(uint64(service.BytesClient)) + " client")
				// TODO: set thickness
				// ent.SetLinkThickness(maltego.GetThickness(uint64(service.BytesServer), min, max))

				if len(service.Banner) > 0 {
					ent.AddDisplayInformation("<pre style='color: dodgerblue;'>"+maltego.EscapeText(html.EscapeString(service.Banner))+"</pre>", "Transferred Data")
				}
			}
		},
		false,
	)
}
