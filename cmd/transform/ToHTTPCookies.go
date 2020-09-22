package transform

import (
	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
)

func toHTTPCookies() {
	maltego.HTTPTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, http *types.HTTP, min, max uint64, path string, ipaddr string) {
			if http.SrcIP == ipaddr || http.DstIP == ipaddr {
				for _, c := range http.ReqCookies {
					addCookie(trx, c, utils.UnixTimeToUTC(http.Timestamp), ipaddr, path, http.Method, http.Host)
				}
				for _, c := range http.ResCookies {
					addCookie(trx, c, utils.UnixTimeToUTC(http.Timestamp), ipaddr, path, http.Method, http.Host)
				}
			}
		},
		false,
	)
}

func addCookie(trx *maltego.Transform, c *types.HTTPCookie, timestamp string, ipaddr string, path string, method string, host string) {
	ent := trx.AddEntityWithPath("netcap.HTTPCookie", c.Name, path)
	ent.AddProperty("ipaddr", "IPAddress", maltego.Strict, ipaddr)
	ent.AddProperty("host", "Host", maltego.Strict, host)
	ent.AddProperty("timestamp", "Timestamp", maltego.Strict, timestamp)
	ent.SetLinkLabel(method)
}