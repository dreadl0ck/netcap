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
		func(lt maltego.LocalTransform, trx *maltego.Transform, profile *types.DeviceProfile, min, max uint64, profilesFile string, mac string) {
			if profile.MacAddr != mac {
				return
			}
			for _, ip := range profile.DeviceIPs {
				if profile, ok := profiles[ip]; ok {

					var (
						ent      *maltego.EntityObj
						dnsNames = strings.Join(profile.DNSNames, "\n")
						val      = profile.Addr
					)
					if len(profile.Geolocation) > 0 {
						val += "\n" + profile.Geolocation
					}
					if len(dnsNames) > 0 {
						val += "\n" + dnsNames
					}
					if resolvers.IsPrivateIP(net.ParseIP(profile.Addr)) {
						ent = trx.AddEntity("netcap.InternalSourceIP", val)
					} else {
						ent = trx.AddEntity("netcap.ExternalSourceIP", val)
					}

					ent.AddProperty("geolocation", "Geolocation", "strict", profile.Geolocation)
					ent.AddProperty("dnsNames", "DNS Names", "strict", dnsNames)

					ent.AddProperty("mac", "MacAddress", "strict", mac)
					ent.AddProperty("ipaddr", "IPAddress", "strict", profile.Addr)
					ent.AddProperty("path", "Path", "strict", profilesFile)
					ent.AddProperty("numPackets", "Num Packets", "strict", strconv.FormatInt(profile.NumPackets, 10))

					ent.SetLinkLabel(strconv.FormatInt(profile.NumPackets, 10) + " pkts\n" + humanize.Bytes(profile.Bytes))
					ent.SetLinkThickness(maltego.GetThickness(uint64(profile.NumPackets), min, max))
				}
			}
		},
	)
}
