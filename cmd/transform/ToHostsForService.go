package transform

import (
	"log"

	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
)

func toHostsForService() {
	var ip, port string

	maltego.ServiceTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, service *types.Service, min, max uint64, profilesFile string, mac string, ipaddr string) {
			if len(ip) == 0 {
				ip = lt.Values["ip"]
				port = lt.Values["port"]
				log.Println("searching for ip", ip, "and port", port)
			}

			if service.IP == ip && service.Port == port {
				for _, f := range service.Flows {
					srcIP, _, _, _ := utils.ParseIdent(f)
					ent := trx.AddEntity("netcap.IPAddr", srcIP)

					ent.AddProperty("timestamp", "Timestamp", "strict", service.Timestamp)
					ent.AddProperty("mac", "MacAddress", "strict", mac)
					ent.AddProperty("ipaddr", "IPAddress", "strict", srcIP)
					ent.AddProperty("path", "Path", "strict", profilesFile)
				}
			}
		},
	)
}
