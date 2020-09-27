package transform

import (
	"strconv"

	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func toApplicationCategories() {

	maltego.IPProfileTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, profile *types.IPProfile, min, max uint64, path string, mac string, ipaddr string) {
			if ipaddr == "" {
				ipaddr = lt.Values[maltego.PropertyIpAddr]
				if ipaddr == "" {
					die("ipaddr property not set", "")
				}
			}
			toCategory(profile, mac, path, trx)
		},
	)
}

func toCategory(p *types.IPProfile, mac, path string, trx *maltego.Transform) {
	for _, proto := range p.Protocols {
		if proto.Category == "" {
			continue
		}

		ent := trx.AddEntityWithPath("netcap.ApplicationCategory", proto.Category, path)
		ent.AddProperty("mac", "MacAddress", maltego.Strict, mac)
		ent.SetLinkLabel(strconv.FormatInt(int64(proto.Packets), 10) + " pkts")
	}
}
