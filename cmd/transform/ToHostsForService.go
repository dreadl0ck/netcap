package transform

import (
	"log"
	"strconv"

	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
)

func toHostsForService() {
	var (
		ip   string
		port int32
	)

	maltego.ServiceTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, service *types.Service, min, max uint64, profilesFile string, mac string, ipaddr string) {
			if len(ip) == 0 {
				ip = lt.Values["ip"]
				portStr := lt.Values["port"]
				portNum, err := strconv.Atoi(portStr)
				if err != nil {
					log.Fatal("invalid port", err)
				}
				port = int32(portNum)
				log.Println("searching for ip", ip, "and port", port)
			}

			if service.IP == ip && service.Port == port {
				for _, f := range service.Flows {
					srcIP, _, _, _ := utils.ParseIdent(f)
					ent := trx.AddEntity("netcap.IPAddr", srcIP)

					ent.AddProperty("timestamp", "Timestamp", "strict", utils.UnixTimeToUTC(service.Timestamp))
					ent.AddProperty("mac", "MacAddress", "strict", mac)
					ent.AddProperty("ipaddr", "IPAddress", "strict", srcIP)
					ent.AddProperty("path", "Path", "strict", profilesFile)
				}
			}
		},
	)
}
