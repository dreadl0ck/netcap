package transform

import (
	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func ToHTTPCookies() {
	maltego.HTTPTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, http *types.HTTP, min, max uint64, profilesFile string, ipaddr string) {
			if http.SrcIP == ipaddr {
				for _, c := range http.ReqCookies {
					addCookie(trx, c, http.Timestamp, ipaddr, profilesFile, http.Method)
				}
				for _, c := range http.ResCookies {
					addCookie(trx, c, http.Timestamp, ipaddr, profilesFile, http.Method)
				}
			}
		},
		false,
	)
}
