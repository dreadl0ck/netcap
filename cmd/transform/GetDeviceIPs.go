package transform

import (
	maltego "github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dustin/go-humanize"
	"net"
	"strconv"
	"strings"
)

func GetDeviceIPs() {
	maltego.DeviceProfileTransform(
		maltego.CountPacketsDeviceIPs,
		func(lt maltego.LocalTransform, trx *maltego.MaltegoTransform, profile  *types.DeviceProfile, min, max uint64, profilesFile string, mac string) {
			if profile.MacAddr == mac {
				for _, ip := range profile.DeviceIPs {

					var ent *maltego.MaltegoEntityObj
					if resolvers.IsPrivateIP(net.ParseIP(ip.Addr)) {
						ent = trx.AddEntity("netcap.InternalDeviceIP", ip.Addr)
						ent.SetType("netcap.InternalDeviceIP")
					} else {
						ent = trx.AddEntity("netcap.ExternalDeviceIP", ip.Addr)
						ent.SetType("netcap.ExternalDeviceIP")
					}
					dnsNames := strings.Join(ip.DNSNames, "\n")
					ent.SetValue(ip.Addr + "\n" + ip.Geolocation + "\n" + dnsNames)

					// di := "<h3>Device IP</h3><p>Timestamp: " + profile.Timestamp + "</p>"
					// ent.AddDisplayInformation(di, "Netcap Info")

					ent.AddProperty("geolocation", "Geolocation", "strict", ip.Geolocation)
					ent.AddProperty("dnsNames", "DNS Names", "strict", dnsNames)

					ent.AddProperty("mac", "MacAddress", "strict", mac)
					ent.AddProperty("ipaddr", "IPAddress", "strict", ip.Addr)
					ent.AddProperty("path", "Path", "strict", profilesFile)
					ent.AddProperty("numPackets", "Num Packets", "strict", strconv.FormatInt(profile.NumPackets, 10))

					ent.SetLinkLabel(strconv.FormatInt(ip.NumPackets, 10) + " pkts\n" + humanize.Bytes(ip.Bytes))
					ent.SetLinkColor("#000000")
					ent.SetLinkThickness(maltego.GetThickness(uint64(ip.NumPackets), min, max))
				}
			}
		},
	)
}
