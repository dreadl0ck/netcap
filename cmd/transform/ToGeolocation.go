package transform

import (
	maltego "github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
	"strconv"
)

func ToGeolocation() {
	maltego.IPTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, profile *types.DeviceProfile, min, max uint64, profilesFile string, mac string, ipaddr string) {
			if profile.MacAddr == mac {
				for _, ip := range profile.Contacts {
					if ip.Addr == ipaddr {
						if ip.Geolocation == "" {
							continue
						}
						addGeolocation(trx, ip, min, max)
					}
				}
				for _, ip := range profile.DeviceIPs {
					if ip.Addr == ipaddr {
						if ip.Geolocation == "" {
							continue
						}
						addGeolocation(trx, ip, min, max)
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
