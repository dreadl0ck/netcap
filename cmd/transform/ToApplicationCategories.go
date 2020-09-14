package transform

import (
	"strconv"

	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func toApplicationCategories() {
	profiles := maltego.LoadIPProfiles()

	maltego.IPTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, profile *types.DeviceProfile, min, max uint64, path string, mac string, ipaddr string) {
			if profile.MacAddr != mac {
				return
			}
			for _, ip := range profile.Contacts {
				if ip == ipaddr {
					toCategory(profiles, ip, mac, path, trx)

					break
				}
			}

			for _, ip := range profile.DeviceIPs {
				if ip == ipaddr {
					toCategory(profiles, ip, mac, path, trx)

					break
				}
			}
		},
	)
}

func toCategory(profiles map[string]*types.IPProfile, ip, mac, path string, trx *maltego.Transform) {
	if p, ok := profiles[ip]; ok {
		for _, proto := range p.Protocols {
			if proto.Category == "" {
				continue
			}

			ent := trx.AddEntityWithPath("netcap.ApplicationCategory", proto.Category, path)

			ent.AddProperty("mac", "MacAddress", maltego.Strict, mac)
			ent.AddProperty("ipaddr", "IPAddress", maltego.Strict, p.Addr)

			ent.SetLinkLabel(strconv.FormatInt(int64(proto.Packets), 10) + " pkts")
		}
	}
}
