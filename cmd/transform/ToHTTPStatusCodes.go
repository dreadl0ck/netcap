package transform

import (
	"strconv"

	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func toHTTPStatusCodes() {
	maltego.HTTPTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, http *types.HTTP, min, max uint64, path string, ipaddr string) {
			if http.SrcIP == ipaddr || http.DstIP == ipaddr {
				if http.StatusCode != 0 {
					val := strconv.FormatInt(int64(http.StatusCode), 10)
					trx.AddEntityWithPath("netcap.HTTPStatusCode", val, path)
				}
			}
		},
		false,
	)
}
