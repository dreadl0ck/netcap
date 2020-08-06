package transform

import (
	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func toSNIs() {
	maltego.IPTransform(
		maltego.CountPacketsContactIPs,
		func(lt maltego.LocalTransform, trx *maltego.Transform, profile *types.DeviceProfile, min, max uint64, profilesFile string, mac string, ipaddr string) {
			if profile.MacAddr == mac {
				for _, ip := range profile.Contacts {
					if ip.Addr == ipaddr {
						if len(ip.SNIs) != 0 {
							for sni, count := range ip.SNIs {
								ent := trx.AddEntity("netcap.Domain", sni)
								ent.SetLinkThickness(maltego.GetThickness(uint64(count), min, max))
							}
						}
					}
				}
				for _, ip := range profile.DeviceIPs {
					if ip.Addr == ipaddr {
						if len(ip.SNIs) != 0 {
							for sni, count := range ip.SNIs {
								ent := trx.AddEntity("netcap.Domain", sni)
								ent.SetLinkThickness(maltego.GetThickness(uint64(count), min, max))
							}
						}
					}
				}
			}
		},
	)
}
