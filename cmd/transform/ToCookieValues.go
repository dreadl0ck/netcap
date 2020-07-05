package transform

import (
	maltego "github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func ToCookieValues() {
	maltego.HTTPTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.MaltegoTransform, http *types.HTTP, min, max uint64, profilesFile string, ipaddr string) {
			cookieName := lt.Values["properties.httpcookie"]
			if http.SrcIP == ipaddr {
				for _, c := range http.ReqCookies {
					if c.Name == cookieName {
						addCookieValue(trx, c, http.Timestamp)
					}
				}
				for _, c := range http.ResCookies {
					if c.Name == cookieName {
						addCookieValue(trx, c, http.Timestamp)
					}
				}
			}
		},
		false,
	)
}

// TODO: set timestamp as property
func addCookieValue(trx *maltego.MaltegoTransform, c *types.HTTPCookie, timestamp string) {
	trx.AddEntity("netcap.HTTPCookieValue", c.Value)
}
