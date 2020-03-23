package main

import (
	"fmt"
	maltego "github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/types"
	"os"
	"strconv"
)

func GetDstPorts() {

	stdOut := os.Stdout
	os.Stdout = os.Stderr
	resolvers.InitServiceDB()
	os.Stdout = stdOut

	maltego.IPTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.MaltegoTransform, profile  *types.DeviceProfile, minPackets, maxPackets uint64, profilesFile string, mac string, ipaddr string) {
			if profile.MacAddr == mac {
				for _, ip := range profile.Contacts {
					if ip.Addr == ipaddr {
						for portStr, port := range ip.DstPorts {
							addDestinationPort(trx, portStr, port, minPackets, maxPackets, ip)
						}
						break
					}
				}
				for _, ip := range profile.DeviceIPs {
					if ip.Addr == ipaddr {
						for portStr, port := range ip.DstPorts {
							addDestinationPort(trx, portStr, port, minPackets, maxPackets, ip)
						}
						break
					}
				}
			}
		},
	)
}

func addDestinationPort(trx *maltego.MaltegoTransform, portStr string, port *types.Port, minPackets, maxPackets uint64, ip *types.IPProfile) {
	ent := trx.AddEntity("netcap.DestinationPort", portStr)
	ent.SetType("netcap.DestinationPort")
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

	// di := "<h3>Port</h3><p>Timestamp: " + ip.TimestampFirst + "</p><p>ServiceName: " + serviceName +"</p>"
	// ent.AddDisplayInformation(di, "Netcap Info")

	escapedName := maltego.EscapeText(portStr + "\n" + serviceName)
	ent.AddProperty("label", "Label", "strict", escapedName)

	ent.SetLinkLabel(strconv.FormatInt(int64(port.NumTotal), 10) + " pkts")
	ent.SetLinkColor("#000000")
	ent.SetLinkThickness(maltego.GetThickness(port.NumTotal, minPackets, maxPackets))
}