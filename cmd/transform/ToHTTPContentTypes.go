package transform

import (
	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func toHTTPContentTypes() {
	maltego.HTTPTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, http *types.HTTP, min, max uint64, path string, ipaddr string) {
			if http.SrcIP == ipaddr || http.DstIP == ipaddr {
				if http.ContentTypeDetected != "" {
					// using ContentTypeDetected instead the one that was set on the HTTP request / response
					ent := trx.AddEntityWithPath("netcap.ContentType", http.ContentTypeDetected, path)
					ent.AddProperty("ipaddr", "IPAddress", maltego.Strict, ipaddr)

				}
				if http.ResContentTypeDetected != "" {
					// using ContentTypeDetected instead the one that was set on the HTTP request / response
					ent := trx.AddEntityWithPath("netcap.ContentType", http.ResContentTypeDetected, path)
					ent.AddProperty("ipaddr", "IPAddress", maltego.Strict, ipaddr)

				}
			}
		},
		false,
	)
}
