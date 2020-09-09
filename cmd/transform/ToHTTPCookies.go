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
			if http.SrcIP != ipaddr {
				return
			}
			for _, c := range http.ReqCookies {
				addCookie(trx, c, utils.UnixTimeToUTC(http.Timestamp), ipaddr, path, http.Method)
			}
			for _, c := range http.ResCookies {
				addCookie(trx, c, utils.UnixTimeToUTC(http.Timestamp), ipaddr, path, http.Method)
			}
		},
		false,
	)
}
