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

func toHTTPHeaders() {
	netmaltego.HTTPTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, http *types.HTTP, min, max uint64, path string, ipaddr string) {
			if http.SrcIP == ipaddr || http.DstIP == ipaddr {
				for name := range http.RequestHeader {
					addHeader(trx, name, utils.UnixTimeToUTC(http.Timestamp), ipaddr, path, http.Method, lt.Value)
				}
				for name := range http.ResponseHeader {
					addHeader(trx, name, utils.UnixTimeToUTC(http.Timestamp), ipaddr, path, http.Method, lt.Value)
				}
			}
		},
		false,
	)
}

func addHeader(trx *maltego.Transform, headerName string, timestamp string, ipaddr string, path string, method string, host string) {
	ent := addEntityWithPath(trx, "netcap.HTTPHeader", headerName, path)
	ent.AddProperty(netmaltego.PropertyIpAddr, netmaltego.PropertyIpAddrLabel, maltego.Strict, ipaddr)
	ent.AddProperty("host", "Host", maltego.Strict, host)
	ent.AddProperty("timestamp", "Timestamp", maltego.Strict, timestamp)
	ent.SetLinkLabel(method)
}
