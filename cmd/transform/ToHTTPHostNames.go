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

func toHTTPHostnames() {
	hostStats := make(map[string]int)

	netmaltego.HTTPTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, http *types.HTTP, min, max uint64, path string, ipaddr string) {
			if http.Host != "" {
				ent := addEntityWithPath(trx, "netcap.Host", http.Host, path)

				hostStats[http.Host]++
				ent.SetLinkLabel(strconv.Itoa(hostStats[http.Host]))
				// ent.SetLinkThickness(maltego.GetThickness(ip.NumPackets))

				ent.AddProperty(netmaltego.PropertyIpAddr, netmaltego.PropertyIpAddrLabel, maltego.Strict, http.DstIP)
			}
		},
		false,
	)
}
