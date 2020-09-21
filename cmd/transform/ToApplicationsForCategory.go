package transform

import (
	"strconv"

	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func toApplicationsForCategory() {
	var (
		category string
	)

	maltego.IPTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, profile *types.IPProfile, min, max uint64, path string, mac string, ipaddr string) {
			if profile.Addr != ipaddr {
				return
			}

			if category == "" {
				category = lt.Values["description"]
			}

			addApplicationForCategory(profile, category, trx, path)
		},
	)
}

func addApplicationForCategory(p *types.IPProfile, category string, trx *maltego.Transform, path string) {
	for protoName, proto := range p.Protocols {
		if proto.Category == category {
			ent := trx.AddEntityWithPath("netcap.Application", protoName, path)
			ent.SetLinkLabel(strconv.FormatInt(int64(proto.Packets), 10) + " pkts")
		}
	}
}
