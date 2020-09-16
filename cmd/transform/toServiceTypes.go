package transform

import (
	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func toServiceTypes() {

	maltego.ServiceTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, service *types.Service, min, max uint64, path string, mac string, ipaddr string) {
			if service.Name != "" {
				trx.AddEntityWithPath("netcap.ServiceType", service.Name, path)
			}
		},
	)
}
