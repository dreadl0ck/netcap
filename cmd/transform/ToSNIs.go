package transform

import (
	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func toSNIs() {

	profiles := maltego.LoadIPProfiles()

	maltego.IPTransform(
		maltego.CountPacketsContactIPs,
		func(lt maltego.LocalTransform, trx *maltego.Transform, profile *types.DeviceProfile, min, max uint64, profilesFile string, mac string, ipaddr string) {
			if profile.MacAddr == mac {
				for _, ip := range profile.Contacts {
					if ip == ipaddr {
						addSNI(profiles, ip, trx, min, max)

					}
				}
				for _, ip := range profile.DeviceIPs {
					if ip == ipaddr {
						addSNI(profiles, ip, trx, min, max)
					}
				}
			}
		},
	)
}

func addSNI(profiles map[string]*types.IPProfile, ip string, trx *maltego.Transform, min, max uint64) {
	if p, ok := profiles[ip]; ok {
		if len(p.SNIs) != 0 {
			for sni, count := range p.SNIs {
				ent := trx.AddEntity("netcap.Domain", sni)
				ent.SetLinkThickness(maltego.GetThickness(uint64(count), min, max))
			}
		}
	}
}