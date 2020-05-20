package transform

import (
	maltego "github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func ToTCPServices() {
	maltego.ServiceTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.MaltegoTransform, service *types.Service, min, max uint64, profilesFile string, mac string, ipaddr string) {
			if service.Protocol == "TCP" {
				ent := trx.AddEntity("netcap.TCPService", service.Hostname)
				ent.SetType("netcap.TCPService")
				ent.SetValue(service.IP + ":" + service.Port)

				ent.SetLinkColor("#000000")
				//ent.SetLinkThickness(maltego.GetThickness(uint64(count), min, max))
			}
		},
	)
}
