package main

import (
	"fmt"
	maltego "github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/types"
	"os"
	"strconv"
)

func GetSrcPorts() {

	stdOut := os.Stdout
	os.Stdout = os.Stderr
	resolvers.InitServiceDB()
	os.Stdout = stdOut

	maltego.IPTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.MaltegoTransform, profile  *types.DeviceProfile, min, max uint64, profilesFile string, mac string, ipaddr string) {
			if profile.MacAddr == mac {
				for _, ip := range profile.Contacts {
					if ip.Addr == ipaddr {
						for portStr, port := range ip.SrcPorts {
							addSourcePort(trx, portStr, port, min, max, ip)
						}
					}
				}
				for _, ip := range profile.DeviceIPs {
					if ip.Addr == ipaddr {
						for portStr, port := range ip.SrcPorts {
							addSourcePort(trx, portStr, port, min, max, ip)
						}
					}
				}
			}
		},
	)
}

func addSourcePort(trx *maltego.MaltegoTransform, portStr string, port *types.Port, min uint64, max uint64, ip *types.IPProfile) {

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

	escapedName := maltego.EscapeText(portStr + "\n" + serviceName)
	ent.AddProperty("label", "Label", "strict", escapedName)

	ent.SetLinkLabel(strconv.FormatInt(int64(port.NumTotal), 10) + " pkts")
	ent.SetLinkColor("#000000")
	ent.SetLinkThickness(maltego.GetThickness(port.NumTotal, min, max))
}