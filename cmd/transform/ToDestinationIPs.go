package transform

import (
	"net"
	"strconv"
	"strings"

	"github.com/dustin/go-humanize"

	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
)

func toDestinationIPs() {
	profiles := maltego.LoadIPProfiles()

	maltego.DeviceProfileTransform(
		maltego.CountPacketsContactIPs,
		func(lt maltego.LocalTransform, trx *maltego.Transform, profile *types.DeviceProfile, min, max uint64, profilesFile string, mac string) {
			if profile.MacAddr == mac {
				for _, ip := range profile.Contacts {
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
							ent = trx.AddEntity("netcap.InternalDestinationIP", val)
						} else {
							ent = trx.AddEntity("netcap.ExternalDestinationIP", val)
						}

						ent.AddProperty("geolocation", "Geolocation", "strict", p.Geolocation)
						ent.AddProperty("dnsNames", "DNS Names", "strict", dnsNames)
						ent.AddProperty("timestamp", "Timestamp", "strict", utils.UnixTimeToUTC(profile.Timestamp))

						ent.AddProperty("mac", "MacAddress", "strict", mac)
						ent.AddProperty("ipaddr", "IPAddress", "strict", p.Addr)
						ent.AddProperty("path", "Path", "strict", profilesFile)
						ent.AddProperty("numPackets", "Num Packets", "strict", strconv.FormatInt(profile.NumPackets, 10))

						ent.SetLinkLabel(strconv.FormatInt(p.NumPackets, 10) + " pkts\n" + humanize.Bytes(p.Bytes))
						ent.SetLinkThickness(maltego.GetThickness(uint64(p.NumPackets), min, max))
					}
				}
			}
		},
	)
}
