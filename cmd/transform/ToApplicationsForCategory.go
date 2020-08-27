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
		func(lt maltego.LocalTransform, trx *maltego.Transform, profile *types.DeviceProfile, min, max uint64, profilesFile string, mac string, ipaddr string) {
			if profile.MacAddr != mac {
				return
			}

			if category == "" {
				category = lt.Values["description"]
			}

			for _, ip := range profile.Contacts {
				if ip == ipaddr {
					addApplicationForCategory(profiles, ip, category, trx)

					break
				}
			}
			for _, ip := range profile.DeviceIPs {
				if ip == ipaddr {
					addApplicationForCategory(profiles, ip, category, trx)

					break
				}
			}
		},
	)
}

func addApplicationForCategory(profiles map[string]*types.IPProfile, ip string, category string, trx *maltego.Transform) {
	if p, ok := profiles[ip]; ok {
		for protoName, proto := range p.Protocols {
			if proto.Category == category {
				ent := trx.AddEntity("maltego.Service", protoName)
				ent.SetLinkLabel(strconv.FormatInt(int64(proto.Packets), 10) + " pkts")
			}
		}
	}
}
