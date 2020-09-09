package transform

import (
	"strconv"

	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
)

func toApplications() {
	profiles := maltego.LoadIPProfiles()

	maltego.IPTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, profile *types.DeviceProfile, min, max uint64, path string, mac string, ipaddr string) {
			if profile.MacAddr != mac {
				return
			}
			for _, ip := range profile.Contacts {
				if ip == ipaddr {
					addApplication(profiles, ip, trx, path)

					break
				}
			}
			for _, ip := range profile.DeviceIPs {
				if ip == ipaddr {
					addApplication(profiles, ip, trx, path)

					break
				}
			}
		},
	)
}

func addApplication(profiles map[string]*types.IPProfile, ip string, trx *maltego.Transform, path string) {
	if p, ok := profiles[ip]; ok {
		for protoName, proto := range p.Protocols {
			ent := trx.AddEntityWithPath("maltego.Service", protoName, path)

			di := "<h3>Application</h3><p>Timestamp first seen: " + utils.UnixTimeToUTC(p.TimestampFirst) + "</p>"
			ent.AddDisplayInformation(di, "Netcap Info")

			ent.SetLinkLabel(strconv.FormatInt(int64(proto.Packets), 10) + " pkts")
		}
	}
}
