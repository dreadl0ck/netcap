package transform

import (
	"strconv"

	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func toApplicationsForCategory() {
	var (
		profiles = maltego.LoadIPProfiles()
		category string
	)

	maltego.IPTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, profile *types.DeviceProfile, min, max uint64, path string, mac string, ipaddr string) {
			if profile.MacAddr != mac {
				return
			}

			if category == "" {
				category = lt.Values["description"]
			}

			for _, ip := range profile.Contacts {
				if ip == ipaddr {
					addApplicationForCategory(profiles, ip, category, trx, path)

					break
				}
			}
			for _, ip := range profile.DeviceIPs {
				if ip == ipaddr {
					addApplicationForCategory(profiles, ip, category, trx, path)

					break
				}
			}
		},
	)
}

func addApplicationForCategory(profiles map[string]*types.IPProfile, ip string, category string, trx *maltego.Transform, path string) {
	if p, ok := profiles[ip]; ok {
		for protoName, proto := range p.Protocols {
			if proto.Category == category {
				ent := trx.AddEntityWithPath("maltego.Service", protoName, path)
				ent.SetLinkLabel(strconv.FormatInt(int64(proto.Packets), 10) + " pkts")
			}
		}
	}
}
