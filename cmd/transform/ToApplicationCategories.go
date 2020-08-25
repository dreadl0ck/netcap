package transform

import (
	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
	"strconv"
)

func toApplicationCategories() {

	profiles := maltego.LoadIPProfiles()

	maltego.IPTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, profile *types.DeviceProfile, min, max uint64, profilesFile string, mac string, ipaddr string) {
			if profile.MacAddr == mac {
				for _, ip := range profile.Contacts {
					if ip == ipaddr {
						toCategory(profiles, ip, mac, profilesFile, trx)

						break
					}
				}

				for _, ip := range profile.DeviceIPs {
					if ip == ipaddr {
						toCategory(profiles, ip, mac, profilesFile, trx)

						break
					}
				}
			}
		},
	)
}

func toCategory(profiles map[string]*types.IPProfile, ip, mac, profilesFile string, trx *maltego.Transform) {
	if p, ok := profiles[ip]; ok {
		for _, proto := range p.Protocols {
			if proto.Category == "" {
				continue
			}

			ent := trx.AddEntity("maltego.Service", proto.Category)

			ent.AddProperty("mac", "MacAddress", "strict", mac)
			ent.AddProperty("ipaddr", "IPAddress", "strict", p.Addr)
			ent.AddProperty("path", "Path", "strict", profilesFile)

			ent.SetLinkLabel(strconv.FormatInt(int64(proto.Packets), 10) + " pkts")
		}
	}
}
