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
	"bytes"
	"encoding/xml"
	"fmt"
	netmaltego "github.com/dreadl0ck/netcap/maltego"
	"log"
	"unicode/utf8"

	"github.com/dreadl0ck/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func toDHCP() {
	results := map[string]int{}

	netmaltego.DHCPV4Transform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, dhcp *types.DHCPv4, min, max uint64, path string, ipaddr string) {
			if dhcp.ClientIP == ipaddr {
				for _, o := range dhcp.Options {
					if utf8.Valid([]byte(o.Data)) && len(o.Data) != 1 {

						// prevent duplicating results
						if _, ok := results[o.Data]; ok {
							return
						}
						results[o.Data]++

						log.Println(o.Data, len(o.Data))

						var buf bytes.Buffer
						err := xml.EscapeText(&buf, []byte(o.Data))
						if err != nil {
							fmt.Println(err)
						}

						var typ string
						switch o.Type {
						case 60:
							typ = "Vendor Class Identifier"
						case 12:
							typ = "Hostname"
						case 15:
							typ = "Domain Name"
						}

						addEntityWithPath(trx, "netcap.Device", typ+": "+buf.String(), path)
					}
				}
			}
		},
		false,
	)

	log.Println(results)
}
