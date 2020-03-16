package main

import (
	maltego "github.com/dreadl0ck/netcap/cmd/maltego/maltego"
	"github.com/dreadl0ck/netcap/types"
	"strconv"
)

func main() {
	maltego.IPTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.MaltegoTransform, profile  *types.DeviceProfile, minPackets, maxPackets uint64, profilesFile string, mac string, ipaddr string) {
			if profile.MacAddr == mac {

				for _, ip := range profile.Contacts {

					if ip.Addr == ipaddr {

						for proto, count := range ip.Protocols {
							ent := trx.AddEntity("maltego.Service", proto)
							ent.SetType("maltego.Service")
							ent.SetValue(proto)

							di := "<h3>Application</h3><p>Timestamp first seen: " + ip.TimestampFirst + "</p>"
							ent.AddDisplayInformation(di, "Netcap Info")

							ent.SetLinkLabel(strconv.FormatInt(int64(count), 10) + " pkts")
							ent.SetLinkColor("#000000")
						}

						break
					}
				}
				for _, ip := range profile.DeviceIPs {

					if ip.Addr == ipaddr {

						for protocol, count := range ip.Protocols {
							ent := trx.AddEntity("maltego.Service", protocol)
							ent.SetType("maltego.Service")
							ent.SetValue(protocol)

							di := "<h3>Application</h3><p>Timestamp first seen: " + ip.TimestampFirst + "</p>"
							ent.AddDisplayInformation(di, "Netcap Info")

							ent.SetLinkLabel(strconv.FormatInt(int64(count), 10) + " pkts")
							ent.SetLinkColor("#000000")
							ent.SetLinkThickness(maltego.GetThickness(count, minPackets, maxPackets))
						}

						break
					}
				}
			}
		},
	)
}