package transform

import (
	maltego "github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func ToParameterValues() {
	maltego.HTTPTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.MaltegoTransform, http *types.HTTP, min, max uint64, profilesFile string, ipaddr string) {
			if http.SrcIP == ipaddr {

				param := lt.Values["properties.httpparameter"]
				for key, val := range http.Parameters {
					if key == param {
						trx.AddEntity("netcap.HTTPParameterValue", val)
					}
				}
			}
		},
		false,
	)
}
