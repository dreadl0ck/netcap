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
	"strconv"

	"github.com/dreadl0ck/maltego"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
)

func toHostsForService() {
	var (
		ip   string
		port int32
	)

	netmaltego.ServiceTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, service *types.Service, min, max uint64, path string, mac string, ipaddr string) {
			if ip == "" {
				ip = lt.Values["ip"]
				portStr := lt.Values["port"]
				if portStr != "" {
					portNum, err := strconv.Atoi(portStr)
					if err != nil {
						log.Fatal("invalid port", err)
					}
					port = int32(portNum)
				}
				log.Println("searching for ip", ip, "and port", port)
			}

			if service.IP == ip && (port == 0 || service.Port == port) {
				log.Println(service.Flows)
				for _, f := range service.Flows {
					srcIP, _, dstIP, _ := utils.ParseFlowIdent(f)
					if srcIP != "" {
						ent := addEntityWithPath(trx, "netcap.IPAddr", srcIP, path)
						ent.AddProperty("timestamp", "Timestamp", maltego.Strict, utils.UnixTimeToUTC(service.Timestamp))
						ent.AddProperty(netmaltego.PropertyIpAddr, netmaltego.PropertyIpAddrLabel, maltego.Strict, srcIP)
					}
					if dstIP != "" {
						ent := addEntityWithPath(trx, "netcap.IPAddr", dstIP, path)
						ent.AddProperty("timestamp", "Timestamp", maltego.Strict, utils.UnixTimeToUTC(service.Timestamp))
						ent.AddProperty(netmaltego.PropertyIpAddr, netmaltego.PropertyIpAddrLabel, maltego.Strict, srcIP)
					}
				}
			}
		},
		false,
	)
}
