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

						for protoName, proto := range ip.Protocols {
							ent := trx.AddEntity("maltego.Service", protoName)
							ent.SetType("maltego.Service")
							ent.SetValue(protoName)

							// di := "<h3>Application</h3><p>Timestamp first seen: " + ip.TimestampFirst + "</p>"
							// ent.AddDisplayInformation(di, "Netcap Info")

							ent.SetLinkLabel(strconv.FormatInt(int64(proto.Packets), 10) + " pkts")
							ent.SetLinkColor("#000000")
						}

						break
					}
				}
				for _, ip := range profile.DeviceIPs {

					if ip.Addr == ipaddr {

						for protoName, proto := range ip.Protocols {
							ent := trx.AddEntity("maltego.Service", protoName)
							ent.SetType("maltego.Service")
							ent.SetValue(protoName)

							// di := "<h3>Application</h3><p>Timestamp first seen: " + ip.TimestampFirst + "</p>"
							// ent.AddDisplayInformation(di, "Netcap Info")

							ent.SetLinkLabel(strconv.FormatInt(int64(proto.Packets), 10) + " pkts")
							ent.SetLinkColor("#000000")
						}

						break
					}
				}
			}
		},
	)
}