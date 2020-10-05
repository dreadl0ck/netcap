package transform

import (
	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func toJA3HashesForProfile() {
	maltego.IPProfileTransform(maltego.CountIPPackets, func(lt maltego.LocalTransform, trx *maltego.Transform, profile *types.IPProfile, min, max uint64, path string, mac string, ip string) {
		if profile.Addr == ip {
			for hash := range profile.Ja3 {
				ent := trx.AddEntityWithPath("netcap.TLSClientHello", hash, path)
				ent.AddProperty("ip", "IP", maltego.Strict, profile.Addr)
			}
		}
	})
}
