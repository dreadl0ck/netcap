package transform

import (
	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
	"log"
)

func toHTTPParameters() {
	maltego.HTTPTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, http *types.HTTP, min, max uint64, path string, ipaddr string) {
			if http.SrcIP == ipaddr || http.DstIP == ipaddr {
				log.Println(ipaddr, http.Parameters)
				for key := range http.Parameters {
					ent := trx.AddEntityWithPath("netcap.HTTPParameter", key, path)
					ent.AddProperty(maltego.PropertyIpAddr, maltego.PropertyIpAddrLabel, maltego.Strict, ipaddr)
					ent.AddProperty("host", "Host", maltego.Strict, http.Host)

					ent.SetLinkLabel(http.Method)
				}
			}
		},
		false,
	)
}
