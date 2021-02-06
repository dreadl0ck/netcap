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
	"log"

	"github.com/dreadl0ck/maltego"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
)

func toDHCPClients() {
	results := map[string]int{}

	netmaltego.DHCPV4Transform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, dhcp *types.DHCPv4, min, max uint64, path string, ipaddr string) {
			// DHCP operations fall into four phases: server discovery, IP lease offer, IP lease request, and IP lease acknowledgement.
			// to identify the client we are only looking for server discovery messages for now
			if dhcp.Operation != 1 {
				return
			}
			log.Println("HW:", dhcp.ClientHWAddr+" FP: "+dhcp.Fingerprint)

			ident := dhcp.ClientHWAddr + "\n" + dhcp.Fingerprint

			// prevent duplicating results
			if _, ok := results[ident]; ok {
				return
			}
			results[ident]++

			// log.Println("ident", ident, dhcp.Fingerprint)

			ent := addEntityWithPath(trx, "netcap.DHCPClient", ident, path)

			ent.AddProperty("timestamp", "Timestamp", maltego.Strict, utils.UnixTimeToUTC(dhcp.Timestamp))
			ent.AddProperty("clientIP", "ClientIP", maltego.Strict, dhcp.ClientIP)
			ent.AddProperty("serverIP", "ServerIP", maltego.Strict, dhcp.NextServerIP)
			ent.AddProperty("fp", "Fingerprint", maltego.Strict, dhcp.Fingerprint)
			ent.AddProperty("clientMac", "ClientHWAddr", maltego.Strict, dhcp.ClientHWAddr)

			for _, o := range dhcp.Options {
				if utils.IsASCII([]byte(o.Data)) && len(o.Data) > 1 {
					switch o.Type {
					case 60:
						ent.AddProperty("vendor", "Vendor", maltego.Strict, o.Data)
					case 12:
						ent.AddProperty("host", "Hostname", maltego.Strict, o.Data)
					case 15:
						ent.AddProperty("domain", "Domain", maltego.Strict, o.Data)
					}
				}
			}
		},
		false,
	)

	fmt.Println(results)
}
