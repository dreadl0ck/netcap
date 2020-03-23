package main

import (
	maltego "github.com/dreadl0ck/netcap/cmd/maltego/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func main() {
	maltego.IPTransform(
		maltego.CountPacketsContactIPs,
		func(lt maltego.LocalTransform, trx *maltego.MaltegoTransform, profile  *types.DeviceProfile, minPackets, maxPackets uint64, profilesFile string, mac string, ipaddr string) {
			if profile.MacAddr == mac {
				for _, ip := range profile.Contacts {
					if ip.Addr == ipaddr {
						if len(ip.SNIs) != 0 {
							for sni, count := range ip.SNIs {
								ent := trx.AddEntity("maltego.Domain", sni)
								ent.SetType("maltego.Domain")
								ent.SetValue(sni)

								// di := "<h3>SNI</h3><p>Timestamp First: " + ip.TimestampFirst + "</p>"
								// ent.AddDisplayInformation(di, "Netcap Info")
								ent.SetLinkColor("#000000")
								ent.SetLinkThickness(maltego.GetThickness(uint64(count), minPackets, maxPackets))
							}
						}
					}
				}
				for _, ip := range profile.DeviceIPs {
					if ip.Addr == ipaddr {
						if len(ip.SNIs) != 0 {
							for sni, count := range ip.SNIs {
								ent := trx.AddEntity("maltego.Domain", sni)
								ent.SetType("maltego.Domain")
								ent.SetValue(sni)

								// di := "<h3>SNI</h3><p>Timestamp First: " + ip.TimestampFirst + "</p>"
								// ent.AddDisplayInformation(di, "Netcap Info")
								ent.SetLinkColor("#000000")
								ent.SetLinkThickness(maltego.GetThickness(uint64(count), minPackets, maxPackets))
							}
						}
					}
				}
			}
		},
	)
}