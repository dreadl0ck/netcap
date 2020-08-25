package transform

import (
	"fmt"
	"github.com/dreadl0ck/netcap/utils"
	"os"
	"strconv"

	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/types"
)

func toSrcPorts() {
	stdOut := os.Stdout
	os.Stdout = os.Stderr
	resolvers.InitServiceDB()
	os.Stdout = stdOut

	maltego.IPTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, profile *types.DeviceProfile, min, max uint64, profilesFile string, mac string, ipaddr string) {
			if profile.MacAddr == mac {
				for _, ip := range profile.Contacts {
					if ip == ipaddr {
						// TODO: load ipProfiles into memory and lookup the ip
						//for portStr, port := range ip.SrcPorts {
						//	addSourcePort(trx, portStr, port, min, max, ip)
						//}
					}
				}
				for _, ip := range profile.DeviceIPs {
					if ip == ipaddr {
						// TODO: load ipProfiles into memory and lookup the ip
						//for portStr, port := range ip.SrcPorts {
						//	addSourcePort(trx, portStr, port, min, max, ip)
						//}
					}
				}
			}
		},
	)
}

func addSourcePort(trx *maltego.Transform, portStr string, port *types.Port, min uint64, max uint64, ip *types.IPProfile) {
	ent := trx.AddEntity("netcap.SourcePort", portStr)
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

	di := "<h3>Port</h3><p>Timestamp: " + utils.UnixTimeToUTC(ip.TimestampFirst) + "</p><p>ServiceName: " + serviceName + "</p>"
	ent.AddDisplayInformation(di, "Netcap Info")

	ent.AddProperty("label", "Label", "strict", portStr+"\n"+serviceName)

	ent.SetLinkLabel(strconv.FormatInt(int64(port.NumTotal), 10) + " pkts")
	ent.SetLinkThickness(maltego.GetThickness(port.NumTotal, min, max))
}
