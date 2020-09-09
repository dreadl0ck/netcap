package transform

import (
	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func toSNIs() {
	profiles := maltego.LoadIPProfiles()

	maltego.IPTransform(
		maltego.CountPacketsContactIPs,
		func(lt maltego.LocalTransform, trx *maltego.Transform, profile *types.DeviceProfile, min, max uint64, path string, mac string, ipaddr string) {
			if profile.MacAddr != mac {
				return
			}
			for _, ip := range profile.Contacts {
				if ip == ipaddr {
					addSNI(profiles, ip, trx, min, max, path)
				}
			}
			for _, ip := range profile.DeviceIPs {
				if ip == ipaddr {
					addSNI(profiles, ip, trx, min, max, path)
				}
			}
		},
	)
}

func addSNI(profiles map[string]*types.IPProfile, ip string, trx *maltego.Transform, min, max uint64, path string) {
	if p, ok := profiles[ip]; ok {
		if len(p.SNIs) != 0 {
			for sni, count := range p.SNIs {
				ent := trx.AddEntityWithPath("netcap.Domain", sni, path)
				ent.SetLinkThickness(maltego.GetThickness(uint64(count), min, max))
			}
		}
	}
}
