package transform

import (
	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func toCookieValues() {
	maltego.HTTPTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, http *types.HTTP, min, max uint64, path string, ipaddr string) {
			if http.SrcIP != ipaddr {
				return
			}
			cookieName := lt.Values["properties.httpcookie"]
			for _, c := range http.ReqCookies {
				if c.Name == cookieName {
					addCookieValue(trx, c, path)
				}
			}
			for _, c := range http.ResCookies {
				if c.Name == cookieName {
					addCookieValue(trx, c, path)
				}
			}
		},
		false,
	)
}

// TODO: set timestamp as property.
func addCookieValue(trx *maltego.Transform, c *types.HTTPCookie, path string) {
	trx.AddEntityWithPath("netcap.HTTPCookieValue", c.Value, path)
}
