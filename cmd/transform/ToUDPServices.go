package transform

import (
	maltego "github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func ToUDPServices() {
	maltego.ServiceTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.MaltegoTransform, service *types.Service, min, max uint64, profilesFile string, mac string, ipaddr string) {
			if service.Protocol == "UDP" {
				ent := trx.AddEntity("netcap.UDPService", service.Hostname)
				ent.SetType("netcap.UDPService")
				ent.SetValue(service.IP + ":" + service.Port)

				ent.SetLinkColor("#000000")
				//ent.SetLinkThickness(maltego.GetThickness(uint64(count), min, max))
			}
		},
	)
}
