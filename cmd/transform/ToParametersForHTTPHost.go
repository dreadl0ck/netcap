package transform

import (
	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func toParametersForHTTPHost() {
	maltego.HTTPTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, http *types.HTTP, min, max uint64, path string, ipaddr string) {
			if http.SrcIP != ipaddr {
				return
			}
			host := lt.Value
			if http.Host == host {
				for key := range http.Parameters {
					ent := trx.AddEntityWithPath("netcap.HTTPParameter", key, path)
					ent.AddProperty("ipaddr", "IPAddress", "strict", ipaddr)

				}
			}
		},
		false,
	)
}
