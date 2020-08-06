package transform

import (
	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func ToCookieValues() {
	maltego.HTTPTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, http *types.HTTP, min, max uint64, profilesFile string, ipaddr string) {
			cookieName := lt.Values["properties.httpcookie"]
			if http.SrcIP == ipaddr {
				for _, c := range http.ReqCookies {
					if c.Name == cookieName {
						addCookieValue(trx, c)
					}
				}
				for _, c := range http.ResCookies {
					if c.Name == cookieName {
						addCookieValue(trx, c)
					}
				}
			}
		},
		false,
	)
}

// TODO: set timestamp as property
func addCookieValue(trx *maltego.Transform, c *types.HTTPCookie) {
	trx.AddEntity("netcap.HTTPCookieValue", c.Value)
}
