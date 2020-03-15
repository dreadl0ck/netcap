package main

import (
	"fmt"
	maltego "github.com/dreadl0ck/netcap/cmd/maltego/maltego"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/types"
	"strconv"
)

func main() {

	resolvers.InitServiceDB()

	maltego.IPTransform(
		nil,
		func(trx *maltego.MaltegoTransform, profile *types.DeviceProfile, minPackets, maxPackets uint64, profilesFile string, mac string, ipaddr string) {
			if profile.MacAddr == mac {
				//for _, ip := range profile.Contacts {
				//	if ip.Addr == ipaddr {
				//		for portStr, port := range ip.DstPorts {
				//			addSourcePort(trx, portStr, port, minPackets, maxPackets, ip)
				//		}
				//		break
				//	}
				//}
				for _, ip := range profile.DeviceIPs {
					if ip.Addr == ipaddr {
						for portStr, port := range ip.DstPorts {
							addSourcePort(trx, portStr, port, minPackets, maxPackets, ip)
						}
						break
					}
				}
			}
		},
	)
}

func addSourcePort(trx *maltego.MaltegoTransform, portStr string, port *types.Port, minPackets uint64, maxPackets uint64, ip *types.IPProfile) {

	ent := trx.AddEntity("netcap.SourcePort", portStr)
	ent.SetType("netcap.SourcePort")
	np, err := strconv.Atoi(portStr)
	if err != nil {
		fmt.Println(err)
		np = 0
	}

	var typ string
	if port.NumTCP > 0 {
		typ = "TCP"
	} else if port.NumUDP > 0 {
		typ = "UDP"
	}
	serviceName := resolvers.LookupServiceByPort(np, typ)
	ent.SetValue(portStr)

	di := "<h3>Port</h3><p>Timestamp: " + ip.TimestampFirst + "</p><p>ServiceName: " + serviceName +"</p>"
	ent.AddDisplayInformation(di, "Netcap Info")

	ent.AddProperty("label", "Label", "strict", portStr + "\n" + serviceName)

	ent.SetLinkLabel(strconv.FormatInt(int64(port.NumTotal), 10) + " pkts")
	ent.SetLinkColor("#000000")
	ent.SetLinkThickness(maltego.GetThickness(port.NumTotal, minPackets, maxPackets))
}