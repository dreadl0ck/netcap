package transform

import (
	maltego "github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
	"strconv"
)

func ToUDPServices() {
	maltego.ServiceTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.MaltegoTransform, service *types.Service, min, max uint64, profilesFile string, mac string, ipaddr string) {
			if service.Protocol == "UDP" {
				ent := trx.AddEntity("netcap.UDPService", service.Hostname)
				ent.SetType("netcap.UDPService")
				ent.SetValue(service.IP + ":" + service.Port)

				ent.AddProperty("timestamp", "Timestamp", "strict", service.Timestamp)
				ent.AddProperty("product", "Product", "strict", service.Product)
				ent.AddProperty("version", "Version", "strict", service.Version)
				ent.AddProperty("protocol", "Protocol", "strict", service.Protocol)
				ent.AddProperty("ip", "IP", "strict", service.IP)
				ent.AddProperty("port", "Port", "strict", service.Port)
				ent.AddProperty("hostname", "Hostname", "strict", service.Hostname)
				ent.AddProperty("bytesclient", "BytesClient", "strict", strconv.Itoa(int(service.BytesClient)))
				ent.AddProperty("bytesserver", "BytesServer", "strict", strconv.Itoa(int(service.BytesServer)))
				ent.AddProperty("vendor", "Vendor", "strict", service.Vendor)
				ent.AddProperty("name", "Name", "strict", service.Name)

				ent.SetLinkColor("#000000")
				//ent.SetLinkThickness(maltego.GetThickness(uint64(count), min, max))
			}
		},
	)
}
