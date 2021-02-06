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
	"net"
	"strconv"
	"strings"

	"github.com/dustin/go-humanize"

	"github.com/dreadl0ck/maltego"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
)

func toDestinationIPs() {
	profiles := netmaltego.LoadIPProfiles()

	netmaltego.DeviceProfileTransform(
		netmaltego.CountPacketsContactIPs,
		func(lt maltego.LocalTransform, trx *maltego.Transform, profile *types.DeviceProfile, min, max uint64, path string, mac string) {
			if profile.MacAddr != mac {
				return
			}
			for _, ip := range profile.Contacts {
				if p, ok := profiles[ip]; ok {

					var (
						ent      *maltego.Entity
						dnsNames = strings.Join(p.DNSNames, "\n")
						val      = p.Addr
					)
					if len(p.Geolocation) > 0 {
						val += "\n" + p.Geolocation
					}
					if len(dnsNames) > 0 {
						val += "\n" + dnsNames
					}

					if resolvers.IsPrivateIP(net.ParseIP(p.Addr)) {
						ent = addEntityWithPath(trx, "netcap.InternalDestinationIP", val, path)
					} else {
						ent = addEntityWithPath(trx, "netcap.ExternalDestinationIP", val, path)
					}

					ent.AddProperty("geolocation", "Geolocation", maltego.Strict, p.Geolocation)
					ent.AddProperty("dnsNames", "DNS Names", maltego.Strict, dnsNames)
					ent.AddProperty("timestamp", "Timestamp", maltego.Strict, utils.UnixTimeToUTC(profile.Timestamp))

					ent.AddProperty("mac", "MacAddress", maltego.Strict, mac)
					ent.AddProperty(netmaltego.PropertyIpAddr, netmaltego.PropertyIpAddrLabel, maltego.Strict, p.Addr)

					ent.AddProperty("numPackets", "Num Packets", maltego.Strict, strconv.FormatInt(profile.NumPackets, 10))

					ent.SetLinkLabel(strconv.FormatInt(p.NumPackets, 10) + " pkts\n" + humanize.Bytes(p.Bytes))
					ent.SetLinkThickness(maltego.GetThickness(uint64(p.NumPackets), min, max))
				}
			}
		},
	)
}
