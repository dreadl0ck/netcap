package transform

import (
	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
)

func toHTTPHeaders() {
	maltego.HTTPTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, http *types.HTTP, min, max uint64, path string, ipaddr string) {
			if http.SrcIP == ipaddr {
				for name := range http.RequestHeader {
					addHeader(trx, name, utils.UnixTimeToUTC(http.Timestamp), ipaddr, path, http.Method, lt.Value)
				}
				for name := range http.ResponseHeader {
					addHeader(trx, name, utils.UnixTimeToUTC(http.Timestamp), ipaddr, path, http.Method, lt.Value)
				}
			}
		},
		false,
	)
}
