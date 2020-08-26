package transform

import (
	"strconv"

	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func toGeolocation() {
	profiles := maltego.LoadIPProfiles()

	maltego.IPTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, profile *types.DeviceProfile, min, max uint64, profilesFile string, mac string, ipaddr string) {
			if profile.MacAddr == mac {
				for _, ip := range profile.Contacts {
					if ip == ipaddr {
						if p, ok := profiles[ip]; ok {
							if p.Geolocation == "" {
								continue
							}
							addGeolocation(trx, p, min, max)
						}
					}
				}
				for _, ip := range profile.DeviceIPs {
					if ip == ipaddr {
						if p, ok := profiles[ip]; ok {
							if p.Geolocation == "" {
								continue
							}
							addGeolocation(trx, p, min, max)
						}
					}
				}
			}
		},
	)
}

func addGeolocation(trx *maltego.Transform, ip *types.IPProfile, min, max uint64) {
	ent := trx.AddEntity("netcap.Location", ip.Geolocation)
	ent.SetLinkLabel(strconv.FormatInt(ip.NumPackets, 10) + " pkts")
	ent.SetLinkThickness(maltego.GetThickness(uint64(ip.NumPackets), min, max))
}
