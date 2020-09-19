package transform

import (
	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func toParameterValues() {
	var (
		paramName string
		host      string
	)
	maltego.HTTPTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, http *types.HTTP, min, max uint64, path string, ipaddr string) {

			if host == "" {
				paramName = lt.Values["properties.httpparameter"]
				host = lt.Values["host"]
				if host == "" {
					die("host not set", "")
				}
			}
			for key, val := range http.Parameters {
				if key == paramName {
					trx.AddEntityWithPath("netcap.HTTPParameterValue", val, path)
				}
			}
		},
		false,
	)
}
