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
)

func toCookieValues() {
	var (
		cookieName string
		host       string
	)

	netmaltego.HTTPTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, http *types.HTTP, min, max uint64, path string, ipaddr string) {
			if host == "" {
				cookieName = lt.Values["properties.httpcookie"]
				host = lt.Values["host"]
				if host == "" {
					maltego.Die("host not set", "")
				}
			}
			if http.Host == host {
				for _, c := range http.ReqCookies {
					if c.Name == cookieName {
						addCookieValue(trx, c, path)
					}
				}
				for _, c := range http.ResCookies {
					if c.Name == cookieName {
						addCookieValue(trx, c, path)
					}
				}
			}
		},
		false,
	)
}

// TODO: set timestamp as property.
func addCookieValue(trx *maltego.Transform, c *types.HTTPCookie, path string) {
	addEntityWithPath(trx, "netcap.HTTPCookieValue", c.Value, path)
}
