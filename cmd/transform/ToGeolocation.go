package transform

import (
	"strconv"

	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func toGeolocation() {
	maltego.IPProfileTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, profile *types.IPProfile, min, max uint64, path string, mac string, ipaddr string) {
			if profile.Addr != ipaddr {
				return
			}
			if profile.Geolocation == "" {
				return
			}
			addGeolocation(trx, profile, min, max, path)
		},
	)
}

func addGeolocation(trx *maltego.Transform, profile *types.IPProfile, min, max uint64, path string) {
	ent := trx.AddEntityWithPath("netcap.Location", profile.Geolocation, path)
	ent.SetLinkLabel(strconv.FormatInt(profile.NumPackets, 10) + " pkts")
	ent.SetLinkThickness(maltego.GetThickness(uint64(profile.NumPackets), min, max))
}
