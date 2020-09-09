package transform

import (
	"net"
	"strconv"
	"strings"

	"github.com/dustin/go-humanize"

	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/types"
)

func toSourceIPs() {
	profiles := maltego.LoadIPProfiles()

	maltego.DeviceProfileTransform(
		maltego.CountPacketsDeviceIPs,
		func(lt maltego.LocalTransform, trx *maltego.Transform, profile *types.DeviceProfile, min, max uint64, path string, mac string) {
			if profile.MacAddr != mac {
				return
			}
			for _, ip := range profile.DeviceIPs {
				if p, ok := profiles[ip]; ok {

					var (
						ent      *maltego.EntityObj
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
						ent = trx.AddEntityWithPath("netcap.InternalSourceIP", val, path)
					} else {
						ent = trx.AddEntityWithPath("netcap.ExternalSourceIP", val, path)
					}

					ent.AddProperty("geolocation", "Geolocation", "strict", p.Geolocation)
					ent.AddProperty("dnsNames", "DNS Names", "strict", dnsNames)

					ent.AddProperty("mac", "MacAddress", "strict", mac)
					ent.AddProperty("ipaddr", "IPAddress", "strict", p.Addr)

					ent.AddProperty("numPackets", "Num Packets", "strict", strconv.FormatInt(p.NumPackets, 10))

					ent.SetLinkLabel(strconv.FormatInt(p.NumPackets, 10) + " pkts\n" + humanize.Bytes(p.Bytes))
					ent.SetLinkThickness(maltego.GetThickness(uint64(p.NumPackets), min, max))
				}
			}
		},
	)
}
