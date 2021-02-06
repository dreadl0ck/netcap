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

func toHTTPCookies() {
	netmaltego.HTTPTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, http *types.HTTP, min, max uint64, path string, ipaddr string) {
			if http.SrcIP == ipaddr || http.DstIP == ipaddr {
				for _, c := range http.ReqCookies {
					addCookie(trx, c, utils.UnixTimeToUTC(http.Timestamp), ipaddr, path, http.Method, http.Host)
				}
				for _, c := range http.ResCookies {
					addCookie(trx, c, utils.UnixTimeToUTC(http.Timestamp), ipaddr, path, http.Method, http.Host)
				}
			}
		},
		false,
	)
}

func addCookie(trx *maltego.Transform, c *types.HTTPCookie, timestamp string, ipaddr string, path string, method string, host string) {
	ent := addEntityWithPath(trx, "netcap.HTTPCookie", c.Name, path)
	ent.AddProperty(netmaltego.PropertyIpAddr, netmaltego.PropertyIpAddrLabel, maltego.Strict, ipaddr)
	ent.AddProperty("host", "Host", maltego.Strict, host)
	ent.AddProperty("timestamp", "Timestamp", maltego.Strict, timestamp)
	ent.SetLinkLabel(method)
}
