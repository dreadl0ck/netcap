package transform

import (
	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func toServerNameIndicators() {
	maltego.IPProfileTransform(maltego.CountIPPackets, func(lt maltego.LocalTransform, trx *maltego.Transform, profile *types.IPProfile, min, max uint64, path string, mac string, ip string) {
		if profile.Addr == ip {
			for s, count := range profile.SNIs {
				ent := trx.AddEntityWithPath("netcap.Domain", s, path)
				ent.SetLinkThickness(maltego.GetThickness(uint64(count), min, max))
			}
		}
	})
}
