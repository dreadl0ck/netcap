package transform

import (
	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func toCookieValues() {
	var (
		cookieName string
		host string
	)

	maltego.HTTPTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, http *types.HTTP, min, max uint64, path string, ipaddr string) {
			if host == "" {
				cookieName = lt.Values["properties.httpcookie"]
				host = lt.Values["host"]
				if host == "" {
					die("host not set", "")
				}
			}
			if http.Host == host {
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
			}
		},
		false,
	)
}


// TODO: set timestamp as property.
func addCookieValue(trx *maltego.Transform, c *types.HTTPCookie, path string) {
	trx.AddEntityWithPath("netcap.HTTPCookieValue", c.Value, path)
}
