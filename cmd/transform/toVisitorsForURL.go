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
	"log"

	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func toVisitorsForURL() {
	var (
		p    = maltego.LoadIPProfiles()
		ips  = make(map[string]struct{})
		url  string
		host string
	)

	maltego.HTTPTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, http *types.HTTP, min, max uint64, path string, ipaddr string) {
			if url == "" {
				url = lt.Values["properties.url"]
				host = lt.Values["host"]
				if url == "" || host == "" {
					die("properties.url or host is not set", "")
				}
				log.Println("got URL", url, "and host", host, maltego.PropertyIpAddr, ipaddr)
			}

			if http.Host == host {
				if http.URL == "" {
					return
				}

				if http.URL != url {
					return
				}

				if http.DstIP != ipaddr {
					return
				}

				// check if srcIP host has already been added
				if _, ok := ips[http.SrcIP]; !ok {
					if profile, exists := p[http.SrcIP]; exists {
						addIPProfile(trx, profile, path, min, max)
					}
					ips[http.SrcIP] = struct{}{}
				}
			}
		},
		false,
	)
}
