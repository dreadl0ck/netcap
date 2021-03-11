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
	"log"
	"net/http"
	"strconv"

	"github.com/dreadl0ck/maltego"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
)

func toHTTPUniformResourceLocators() {
	urlStats := make(map[string]int)

	netmaltego.HTTPTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, h *types.HTTP, min, max uint64, path string, ipaddr string) {
			if h.SrcIP == ipaddr || h.DstIP == ipaddr {
				if h.URL == "" {
					return
				}

				bareURL := utils.StripQueryString(h.URL)
				log.Println(bareURL)

				ent := addEntityWithPath(trx, "netcap.URL", bareURL, path)

				// since netcap.URL is inheriting from maltego.URL, in order to set the URL field correctly, we need to prefix the id with properties.
				ent.AddProperty("properties.url", "URL", maltego.Strict, bareURL)
				ent.AddProperty("host", "Host", maltego.Strict, h.Host)
				ent.AddProperty(netmaltego.PropertyIpAddr, netmaltego.PropertyIpAddrLabel, maltego.Strict, ipaddr)

				urlStats[bareURL]++
				ent.SetLinkLabel(strconv.Itoa(urlStats[bareURL]) + "\n" + h.Method)

				// ent.AddDisplayInformation(createURLTableHTML(h, "SourceIP", h.SrcIP), "Visitors")
				// ent.AddDisplayInformation(createURLTableHTML(h, "DestinationIP", h.DstIP), "Providers")

				ent.AddDisplayInformation("<pre>"+utils.UnixTimeToUTC(h.Timestamp)+"    |    "+h.SrcIP+"    |    "+h.Method+"    |    "+strconv.Itoa(int(h.StatusCode))+"    |    "+http.StatusText(int(h.StatusCode))+"<br>", "Visitors")
				ent.AddDisplayInformation("<pre>"+utils.UnixTimeToUTC(h.Timestamp)+"    |    "+h.DstIP+"    |    "+h.Method+"    |    "+strconv.Itoa(int(h.StatusCode))+"    |    "+http.StatusText(int(h.StatusCode))+"<br>", "Providers")
			}
		},
		false,
	)
}

//func createURLTableHTML(h *types.HTTP, ipType, ip string) string {
//	out := []string{"<table style='width:100%'>"}
//
//	out = append(out, `<tr>
//    <th>Timestamp</th>
//    <th>`+ipType+`</th>
//	<th>StatusCode</th>
//	<th>StatusText</th>
//  </tr>`)
//
//	out = append(out, "<tr><td>"+utils.UnixTimeToUTC(h.Timestamp)+"</td><td>"+ip+"</td><td>"+strconv.Itoa(int(h.StatusCode))+"</td><td>"+http.StatusText(int(h.StatusCode))+"</td></tr>")
//
//	// colors
//	// out = append(out, "<tr><td style='color:red'>"+k+"</td><td>"+v+"</td></tr>")
//
//	// out = append(out, "</table>")
//
//	return strings.Join(out, "")
//}
