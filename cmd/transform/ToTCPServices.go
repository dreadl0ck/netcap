package transform

import (
	maltego "github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
	"strconv"
)

func ToTCPServices() {
	maltego.ServiceTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.MaltegoTransform, service *types.Service, min, max uint64, profilesFile string, mac string, ipaddr string) {
			if service.Protocol == "TCP" {

				ent := trx.AddEntity("netcap.TCPService", service.IP + ":" + service.Port)
				ent.SetType("netcap.TCPService")

				val := service.IP + ":" + service.Port
				if len(service.Vendor) > 0 {
					val += "\n" + service.Vendor
				}
				if len(service.Product) > 0 {
					val += "\n" + service.Product
				}
				if len(service.Name) > 0 {
					val += "\n" + service.Name
				}
				val = maltego.EscapeText(val)
				ent.SetValue(val)

				ent.AddProperty("timestamp", "Timestamp", "strict", service.Timestamp)
				ent.AddProperty("product", "Product", "strict", maltego.EscapeText(service.Product))
				ent.AddProperty("version", "Version", "strict", maltego.EscapeText(service.Version))
				ent.AddProperty("protocol", "Protocol", "strict", service.Protocol)
				ent.AddProperty("ip", "IP", "strict", service.IP)
				ent.AddProperty("port", "Port", "strict", service.Port)
				ent.AddProperty("hostname", "Hostname", "strict", maltego.EscapeText(service.Hostname))
				ent.AddProperty("bytesclient", "BytesClient", "strict", strconv.Itoa(int(service.BytesClient)))
				ent.AddProperty("bytesserver", "BytesServer", "strict", strconv.Itoa(int(service.BytesServer)))
				ent.AddProperty("vendor", "Vendor", "strict", maltego.EscapeText(service.Vendor))
				ent.AddProperty("name", "Name", "strict", maltego.EscapeText(service.Name))

				if len(service.Banner) > 0 {
					ent.SetNote(maltego.EscapeText(string(service.Banner)))
				}

				ent.SetLinkColor("#000000")
				//ent.SetLinkThickness(maltego.GetThickness(uint64(count), min, max))
			}
		},
	)
}
