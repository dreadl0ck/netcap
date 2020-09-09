package transform

import (
	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func toParameterValues() {
	maltego.HTTPTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, http *types.HTTP, min, max uint64, path string, ipaddr string) {
			if http.SrcIP != ipaddr {
				return
			}
			param := lt.Values["properties.httpparameter"]
			for key, val := range http.Parameters {
				if key == param {
					trx.AddEntityWithPath("netcap.HTTPParameterValue", val, path)
				}
			}
		},
		false,
	)
}
