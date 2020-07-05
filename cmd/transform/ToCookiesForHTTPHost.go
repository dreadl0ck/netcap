package transform

import (
	maltego "github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func ToCookiesForHTTPHost() {
	maltego.HTTPTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.MaltegoTransform, http *types.HTTP, min, max uint64, profilesFile string, ipaddr string) {
			if http.SrcIP == ipaddr {
				host := lt.Value
				if http.Host == host {
					for _, c := range http.ReqCookies {
						addCookie(trx, c, http.Timestamp, ipaddr, profilesFile, http.Method)
					}
					for _, c := range http.ResCookies {
						addCookie(trx, c, http.Timestamp, ipaddr, profilesFile, http.Method)
					}
				}
			}
		},
		false,
	)
}

func addCookie(trx *maltego.MaltegoTransform, c *types.HTTPCookie, timestamp string, ipaddr string, profilesFile string, method string) {
	ent := trx.AddEntity("netcap.HTTPCookie", c.Name)
	ent.AddProperty("ipaddr", "IPAddress", "strict", ipaddr)
	ent.AddProperty("path", "Path", "strict", profilesFile)
	ent.AddProperty("timestamp", "Timestamp", "strict", timestamp)
	ent.SetLinkLabel(method)
}
