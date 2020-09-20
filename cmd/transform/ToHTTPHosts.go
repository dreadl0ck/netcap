package transform

import (
	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func toHTTPHosts() {
	maltego.HTTPTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, http *types.HTTP, min, max uint64, path string, ipaddr string) {
			if http.SrcIP != ipaddr {
				return
			}
			if http.Host != "" {
				ent := trx.AddEntityWithPath("netcap.Website", http.Host, path)
				ent.AddProperty("ipaddr", "IPAddress", maltego.Strict, ipaddr)
			}
		},
		false,
	)
}
