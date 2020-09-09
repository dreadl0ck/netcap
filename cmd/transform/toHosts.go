package transform

import (
	"strconv"

	"github.com/dustin/go-humanize"

	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func toHosts() {
	maltego.IPProfileTransform(maltego.CountIPPackets, func(lt maltego.LocalTransform, trx *maltego.Transform, profile *types.IPProfile, min, max uint64, path string, mac string, ip string) {
		ident := profile.Addr + "\n" + profile.Geolocation
		ent := trx.AddEntityWithPath("netcap.IPProfile", ident, path)

		ent.SetLinkLabel(strconv.FormatInt(profile.NumPackets, 10) + " pkts\n" + humanize.Bytes(profile.Bytes))
		ent.SetLinkThickness(maltego.GetThickness(uint64(profile.NumPackets), min, max))
	})
}
