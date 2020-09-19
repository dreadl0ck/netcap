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
		func(lt maltego.LocalTransform, trx *maltego.Transform, service *types.Service, min, max uint64, path string, mac string, ipaddr string) {
			if ip == "" {
				ip = lt.Values["ip"]
				portStr := lt.Values["port"]
				if portStr != "" {
					portNum, err := strconv.Atoi(portStr)
					if err != nil {
						log.Fatal("invalid port", err)
					}
					port = int32(portNum)
				}
				log.Println("searching for ip", ip, "and port", port)
			}

			if service.IP == ip && (port == 0 || service.Port == port) {
				log.Println(service.Flows)
				for _, f := range service.Flows {
					srcIP, _, dstIP, _ := utils.ParseFlowIdent(f)
					if srcIP != "" {
						ent := trx.AddEntityWithPath("netcap.IPAddr", srcIP, path)
						ent.AddProperty("timestamp", "Timestamp", maltego.Strict, utils.UnixTimeToUTC(service.Timestamp))
						ent.AddProperty("ipaddr", "IPAddress", maltego.Strict, srcIP)
					}
					if dstIP != "" {
						ent := trx.AddEntityWithPath("netcap.IPAddr", dstIP, path)
						ent.AddProperty("timestamp", "Timestamp", maltego.Strict, utils.UnixTimeToUTC(service.Timestamp))
						ent.AddProperty("ipaddr", "IPAddress", maltego.Strict, srcIP)
					}
				}
			}
		},
	)
}
